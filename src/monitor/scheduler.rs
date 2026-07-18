//! Batch scheduler and task orchestration.

use std::{future::Future, time::Instant};

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
        run_stage(db, &batch, "dns", dns::run(db, config, &batch)).await?;
        run_stage(db, &batch, "port_scan", ports::run(db, config, &batch)).await?;
        run_stage(
            db,
            &batch,
            "fingerprint",
            fingerprint::run(db, config, &batch),
        )
        .await?;

        info!(batch = %batch.id, "task4 web enum and task6 detailed fingerprint starting; task5 vuln scan will start after task4");
        let web_then_vuln_task = async {
            run_stage(db, &batch, "web_enum", web_enum::run(db, config, &batch)).await?;
            run_stage(db, &batch, "vulnerability_scan", vuln::run(db, config, &batch)).await
        };
        let detailed_fingerprint_task = run_stage(
            db,
            &batch,
            "detailed_fingerprint",
            detailed_fingerprint::run(db, config, &batch),
        );
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
            finalize(db, config, &batch).await?;
            return Err(error);
        }
    };

    db.finish_batch(&batch.id, status, None)?;
    finalize(db, config, &batch).await?;
    info!(
        batch = %batch.id,
        started_at = %local_time::utc_to_local(&batch.started_at),
        "monitoring batch finished"
    );
    Ok(())
}

/// Builds the report package and sends optional email notification.
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

/// Runs a named pipeline stage and persists its lifecycle for the dashboard.
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
