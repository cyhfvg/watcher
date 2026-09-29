//! Batch scheduler and task orchestration.

use std::{
    future::{Future, pending},
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use tokio::{sync::Notify, time::sleep};
use tracing::{error, info, warn};

use crate::{
    config::AppConfig,
    db::Database,
    local_time,
    monitor::{detailed_fingerprint, dns, fingerprint, ports, vuln, web_enum},
    notify, report,
};

/// Runs the long-lived daemon loop; when `once` is true, exits after one
/// batch.
///
/// # Arguments
///
/// - `db`: owned database handle reused across the loop.
/// - `config`: schedule interval and task configuration.
/// - `once`: when `true`, return after a single batch.
///
/// # Returns
///
/// `Ok(())` when the loop ends normally.
///
/// # Errors
///
/// Returns an error only when `once` is true and that batch fails. A
/// long-running loop logs the failure and continues. An interval timeout or
/// shutdown signal still waits for the in-flight batch, then marks the batch
/// interrupted.
///
/// # Examples
///
/// ```no_run
/// # use watcher::{config::AppConfig, db::Database, monitor::scheduler};
/// # async fn demo(db: Database, config: AppConfig) -> anyhow::Result<()> {
/// scheduler::run_daemon(db, config, true).await?;
/// # Ok(())
/// # }
/// ```
pub async fn run_daemon(db: Database, config: AppConfig, once: bool) -> anyhow::Result<()> {
    let shutdown = process_shutdown();
    loop {
        if shutdown.requested() {
            info!("shutdown requested; daemon loop exiting");
            break;
        }
        let started = Instant::now();
        let interval = config.interval();
        if let Err(error) = drive_until_stop(&db, &config, Some(interval)).await {
            error!(%error, "batch failed; continuing unless this is a one-shot run");
            if once {
                return Err(error);
            }
        }
        if once || shutdown.requested() {
            break;
        }
        let elapsed = started.elapsed();
        if elapsed < interval {
            tokio::select! {
                _ = sleep(interval - elapsed) => {}
                _ = shutdown.cancelled() => break,
            }
        }
    }
    Ok(())
}

/// Runs one full monitoring batch, then report / email finalization.
///
/// A shutdown signal uses the same stop path as an interval timeout: set the
/// stop flag, let the in-flight stage finish, then interrupt the batch.
///
/// # Arguments
///
/// - `db`: database handle.
/// - `config`: per-stage task configuration.
///
/// # Returns
///
/// `Ok(())` when the batch finishes or is interrupted by stop.
///
/// # Errors
///
/// Returns an error if batch creation, any pipeline stage, or finalization
/// fails.
///
/// # Examples
///
/// ```no_run
/// # use watcher::{config::AppConfig, db::Database, monitor::scheduler};
/// # async fn demo(db: &Database, config: &AppConfig) -> anyhow::Result<()> {
/// scheduler::run_single_batch(db, config).await?;
/// # Ok(())
/// # }
/// ```
pub async fn run_single_batch(db: &Database, config: &AppConfig) -> anyhow::Result<()> {
    drive_until_stop(db, config, None).await
}

const STOP_REASON: &str = "stop requested before batch finalized";

struct Shutdown {
    flag: AtomicBool,
    notify: Notify,
}

impl Shutdown {
    fn requested(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    fn request(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            if self.requested() {
                return;
            }
            notified.await;
        }
    }
}

fn process_shutdown() -> Arc<Shutdown> {
    static HANDLE: LazyLock<Arc<Shutdown>> = LazyLock::new(|| {
        let shutdown = Arc::new(Shutdown {
            flag: AtomicBool::new(false),
            notify: Notify::new(),
        });
        let listener = Arc::clone(&shutdown);
        tokio::spawn(async move {
            wait_for_shutdown_signal().await;
            listener.request();
        });
        shutdown
    });
    Arc::clone(&HANDLE)
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                warn!(%error, "failed to listen for SIGTERM");
                return;
            }
        };
        let mut interrupt = match signal(SignalKind::interrupt()) {
            Ok(signal) => signal,
            Err(error) => {
                warn!(%error, "failed to listen for SIGINT");
                let _ = terminate.recv().await;
                return;
            }
        };
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            warn!(%error, "failed to listen for ctrl-c");
        }
    }
}

async fn drive_until_stop(
    db: &Database,
    config: &AppConfig,
    interval: Option<std::time::Duration>,
) -> anyhow::Result<()> {
    let work = execute_batch(db, config);
    tokio::pin!(work);
    let shutdown = process_shutdown();
    let mut stop_sent = false;
    let deadline = async {
        match interval {
            Some(interval) => sleep(interval).await,
            None => pending::<()>().await,
        }
    };
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            biased;
            result = &mut work => return result,
            _ = shutdown.cancelled(), if !stop_sent => {
                warn!("shutdown signal received; requesting cooperative batch stop");
                db.request_batch_stop(None)?;
                stop_sent = true;
            }
            _ = &mut deadline, if !stop_sent => {
                warn!("batch exceeded scheduler interval; requesting cooperative stop");
                db.request_batch_stop(None)?;
                stop_sent = true;
            }
        }
    }
}

async fn execute_batch(db: &Database, config: &AppConfig) -> anyhow::Result<()> {
    let batch = db.create_batch()?;
    db.prune_history(30)?;
    if batch_should_stop(db, &batch.id)? {
        return db.finalize_stopped_batch(&batch.id, STOP_REASON);
    }

    let task_result: anyhow::Result<bool> = async {
        if guarded_stage(db, &batch, "dns", dns::run(db, config, &batch))
            .await?
            .is_none()
        {
            return Ok(false);
        }
        if guarded_stage(db, &batch, "port_scan", ports::run(db, config, &batch))
            .await?
            .is_none()
        {
            return Ok(false);
        }
        if guarded_stage(
            db,
            &batch,
            "fingerprint",
            fingerprint::run(db, config, &batch),
        )
        .await?
        .is_none()
        {
            return Ok(false);
        }

        info!(batch = %batch.id, "task4 web enum and task6 detailed fingerprint starting; task5 vuln scan will start after task4");
        let web_then_vuln_task = async {
            if guarded_stage(db, &batch, "web_enum", web_enum::run(db, config, &batch))
                .await?
                .is_none()
            {
                return Ok::<bool, anyhow::Error>(false);
            }
            Ok::<bool, anyhow::Error>(guarded_stage(
                db,
                &batch,
                "vulnerability_scan",
                vuln::run(db, config, &batch),
            )
            .await?
            .is_some())
        };
        let detailed_fingerprint_task = async {
            Ok::<bool, anyhow::Error>(guarded_stage(
                db,
                &batch,
                "detailed_fingerprint",
                detailed_fingerprint::run(db, config, &batch),
            )
            .await?
            .is_some())
        };
        let (web_then_vuln_result, detailed_fingerprint_result) =
            tokio::join!(web_then_vuln_task, detailed_fingerprint_task);
        Ok(web_then_vuln_result? && detailed_fingerprint_result?)
    }
    .await;

    match task_result {
        Ok(true) => {}
        Ok(false) => {
            warn!(batch = %batch.id, "batch interrupted before finalization");
            db.finalize_stopped_batch(&batch.id, STOP_REASON)?;
            return Ok(());
        }
        Err(error) => {
            error!(batch = %batch.id, %error, "batch tasks failed");
            db.finish_batch(&batch.id, "failed", Some(&error.to_string()))?;
            finalize(db, config, &batch).await?;
            return Err(error);
        }
    }

    db.finish_batch(&batch.id, "completed", None)?;
    finalize(db, config, &batch).await?;
    info!(
        batch = %batch.id,
        started_at = %local_time::utc_to_local(&batch.started_at),
        "monitoring batch finished"
    );
    Ok(())
}

fn batch_should_stop(db: &Database, batch_id: &str) -> anyhow::Result<bool> {
    if process_shutdown().requested() {
        db.request_batch_stop(Some(batch_id))?;
    }
    db.should_stop_batch(batch_id)
}

async fn guarded_stage<T, F>(
    db: &Database,
    batch: &crate::models::BatchContext,
    stage: &str,
    operation: F,
) -> anyhow::Result<Option<T>>
where
    F: Future<Output = anyhow::Result<T>>,
{
    if batch_should_stop(db, &batch.id)? {
        return Ok(None);
    }
    let value = run_stage(db, batch, stage, operation).await?;
    if batch_should_stop(db, &batch.id)? {
        db.finish_batch_stage(&batch.id, stage, "interrupted", Some(STOP_REASON))?;
        return Ok(None);
    }
    Ok(Some(value))
}

/// Builds the report package and sends an optional email notification.
///
/// Email failure is recorded as a stage `warning` and does not fail the
/// whole batch.
///
/// # Arguments
///
/// - `db`: database handle.
/// - `config`: report and email configuration.
/// - `batch`: current batch context.
///
/// # Returns
///
/// `Ok(())` when the report stage succeeds.
///
/// # Errors
///
/// Returns an error if report packaging fails.
///
/// # Examples
///
/// ```text
/// finalize(db, config, &batch).await?;
/// ```
async fn finalize(
    db: &Database,
    config: &AppConfig,
    batch: &crate::models::BatchContext,
) -> anyhow::Result<()> {
    let package = run_stage(db, batch, "report", async {
        let package = report::build_report_package(db, config, Some(&batch.id))?;
        db.set_batch_report(&batch.id, &package.zip_path)?;
        Ok(package)
    })
    .await?;

    db.start_batch_stage(&batch.id, "email_notification")?;
    let task_started = Instant::now();
    info!(batch = %batch.id, "email notification started");
    if let Err(error) = notify::email::send_summary(db, config, &batch.id, &package.zip_path).await
    {
        let error_chain = format_error_chain(error.as_ref());
        db.finish_batch_stage(
            &batch.id,
            "email_notification",
            "warning",
            Some(&error_chain),
        )?;
        warn!(
            batch = %batch.id,
            error = %error,
            error_chain = %error_chain,
            smtp_host = %config.email.smtp_host,
            smtp_port = config.email.smtp_port,
            smtp_security = %config.email.smtp_security,
            from = %config.email.from,
            recipients = ?config.email.to,
            attachment = %package.zip_path.display(),
            "email notification failed"
        );
        info!(
            batch = %batch.id,
            elapsed_ms = task_started.elapsed().as_millis(),
            "task8 email notification finished with warning"
        );
    } else {
        db.finish_batch_stage(&batch.id, "email_notification", "completed", None)?;
        info!(
            batch = %batch.id,
            elapsed_ms = task_started.elapsed().as_millis(),
            "task8 email notification finished"
        );
    }
    Ok(())
}

/// Runs a named pipeline stage and writes its lifecycle to the dashboard.
///
/// # Arguments
///
/// - `db`: database handle.
/// - `batch`: current batch.
/// - `stage`: stable stage name.
/// - `operation`: stage async operation.
///
/// # Returns
///
/// The operation result when the stage succeeds.
///
/// # Errors
///
/// Returns an error if writing stage status fails or `operation` returns an
/// error.
///
/// # Examples
///
/// ```text
/// run_stage(db, &batch, "dns", dns::run(db, config, &batch)).await?;
/// ```
async fn run_stage<T, F>(
    db: &Database,
    batch: &crate::models::BatchContext,
    stage: &str,
    operation: F,
) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    db.start_batch_stage(&batch.id, stage)?;
    let started = Instant::now();
    info!(batch = %batch.id, stage, "monitoring stage started");
    match operation.await {
        Ok(value) => {
            db.finish_batch_stage(&batch.id, stage, "completed", None)?;
            info!(
                batch = %batch.id,
                stage,
                elapsed_ms = started.elapsed().as_millis(),
                "monitoring stage completed"
            );
            Ok(value)
        }
        Err(error) => {
            let detail = error.to_string();
            db.finish_batch_stage(&batch.id, stage, "failed", Some(&detail))?;
            error!(
                batch = %batch.id,
                stage,
                elapsed_ms = started.elapsed().as_millis(),
                %error,
                "monitoring stage failed"
            );
            Err(error)
        }
    }
}

/// Formats a full anyhow error chain as diagnostic text.
///
/// # Arguments
///
/// - `error`: error object.
///
/// # Returns
///
/// Error chain joined with ` | caused by: `.
///
/// # Examples
///
/// ```text
/// let detail = format_error_chain(error.as_ref());
/// ```
fn format_error_chain(error: &dyn std::error::Error) -> String {
    let mut messages = vec![error.to_string()];
    let mut current = error.source();
    while let Some(source) = current {
        messages.push(source.to_string());
        current = source.source();
    }
    messages.join(" | caused by: ")
}
