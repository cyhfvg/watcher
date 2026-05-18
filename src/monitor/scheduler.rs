//! Batch scheduler and task orchestration.

use std::time::Instant;

use tokio::time::{sleep, timeout};
use tracing::{error, info, warn};

use crate::{
    config::AppConfig,
    db::Database,
    local_time,
    monitor::{detailed_fingerprint, dns, fingerprint, ports, vuln, web_enum},
    notify, report,
};

/// Runs the long-lived daemon loop or exits after one batch when `once` is true.
pub async fn run_daemon(db: Database, config: AppConfig, once: bool) -> anyhow::Result<()> {
    loop {
        let started = Instant::now();
        let interval = config.interval();
        match timeout(interval, run_single_batch(&db, &config)).await {
            Ok(result) => result?,
            Err(_) => {
                warn!(
                    "batch exceeded scheduler interval; stop requested and next batch will start"
                );
                db.request_batch_stop(None)?;
            }
        }

        if once {
            break;
        }

        let elapsed = started.elapsed();
        if elapsed < interval {
            sleep(interval - elapsed).await;
        }
    }
    Ok(())
}

/// Runs one complete monitoring batch and performs report/email finalization.
pub async fn run_single_batch(db: &Database, config: &AppConfig) -> anyhow::Result<()> {
    let batch = db.create_batch()?;
    info!(batch = %batch.id, "monitoring batch started");

    let task_result = async {
        let task_started = Instant::now();
        info!(batch = %batch.id, "task1 dns resolution started");
        dns::run(db, config, &batch).await?;
        info!(
            batch = %batch.id,
            elapsed_ms = task_started.elapsed().as_millis(),
            "task1 dns resolution finished"
        );

        let task_started = Instant::now();
        info!(batch = %batch.id, "task2 port scan started");
        ports::run(db, config, &batch).await?;
        info!(
            batch = %batch.id,
            elapsed_ms = task_started.elapsed().as_millis(),
            "task2 port scan finished"
        );

        let task_started = Instant::now();
        info!(batch = %batch.id, "task3 service fingerprint started");
        fingerprint::run(db, config, &batch).await?;
        info!(
            batch = %batch.id,
            elapsed_ms = task_started.elapsed().as_millis(),
            "task3 service fingerprint finished"
        );

        info!(batch = %batch.id, "task4 web enum and task6 detailed fingerprint starting; task5 vuln scan will start after task4");
        let web_then_vuln_task = async {
            let task_started = Instant::now();
            info!(batch = %batch.id, "task4 web enum started");
            let result = web_enum::run(db, config, &batch).await;
            match &result {
                Ok(()) => info!(
                    batch = %batch.id,
                    elapsed_ms = task_started.elapsed().as_millis(),
                    "task4 web enum finished"
                ),
                Err(error) => error!(
                    batch = %batch.id,
                    elapsed_ms = task_started.elapsed().as_millis(),
                    %error,
                    "task4 web enum failed"
                ),
            }
            result?;

            let task_started = Instant::now();
            info!(batch = %batch.id, "task5 vuln scan started");
            let result = vuln::run(db, config, &batch).await;
            match &result {
                Ok(()) => info!(
                    batch = %batch.id,
                    elapsed_ms = task_started.elapsed().as_millis(),
                    "task5 vuln scan finished"
                ),
                Err(error) => error!(
                    batch = %batch.id,
                    elapsed_ms = task_started.elapsed().as_millis(),
                    %error,
                    "task5 vuln scan failed"
                ),
            }
            result
        };
        let detailed_fingerprint_task = async {
            let task_started = Instant::now();
            info!(batch = %batch.id, "task6 detailed fingerprint started");
            let result = detailed_fingerprint::run(db, config, &batch).await;
            match &result {
                Ok(()) => info!(
                    batch = %batch.id,
                    elapsed_ms = task_started.elapsed().as_millis(),
                    "task6 detailed fingerprint finished"
                ),
                Err(error) => error!(
                    batch = %batch.id,
                    elapsed_ms = task_started.elapsed().as_millis(),
                    %error,
                    "task6 detailed fingerprint failed"
                ),
            }
            result
        };
        let (web_then_vuln_result, detailed_fingerprint_result) =
            tokio::join!(web_then_vuln_task, detailed_fingerprint_task);
        web_then_vuln_result?;
        detailed_fingerprint_result?;
        Ok::<(), anyhow::Error>(())
    }
    .await;

    let status = match task_result {
        Ok(()) => "completed",
        Err(error) => {
            error!(batch = %batch.id, %error, "batch tasks failed");
            db.finish_batch(&batch.id, "failed", Some(&error.to_string()))?;
            finalize(db, config, &batch.id).await?;
            return Err(error);
        }
    };

    db.finish_batch(&batch.id, status, None)?;
    finalize(db, config, &batch.id).await?;
    info!(
        batch = %batch.id,
        started_at = %local_time::utc_to_local(&batch.started_at),
        "monitoring batch finished"
    );
    Ok(())
}

/// Builds the report package and sends optional email notification.
async fn finalize(db: &Database, config: &AppConfig, batch_id: &str) -> anyhow::Result<()> {
    let task_started = Instant::now();
    info!(batch = %batch_id, "task7 report packaging started");
    let package = report::build_report_package(db, config, Some(batch_id))?;
    db.set_batch_report(batch_id, &package.zip_path)?;
    info!(
        batch = %batch_id,
        elapsed_ms = task_started.elapsed().as_millis(),
        report_zip = %package.zip_path.display(),
        "task7 report packaging finished"
    );

    let task_started = Instant::now();
    info!(batch = %batch_id, "task8 email notification started");
    if let Err(error) = notify::email::send_summary(db, config, batch_id, &package.zip_path).await {
        let error_chain = format_error_chain(error.as_ref());
        warn!(
            batch = %batch_id,
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
            batch = %batch_id,
            elapsed_ms = task_started.elapsed().as_millis(),
            "task8 email notification finished with warning"
        );
    } else {
        info!(
            batch = %batch_id,
            elapsed_ms = task_started.elapsed().as_millis(),
            "task8 email notification finished"
        );
    }
    Ok(())
}

/// Formats the full anyhow error chain for diagnostics.
fn format_error_chain(error: &dyn std::error::Error) -> String {
    let mut messages = vec![error.to_string()];
    let mut current = error.source();
    while let Some(source) = current {
        messages.push(source.to_string());
        current = source.source();
    }
    messages.join(" | caused by: ")
}
