//! SMTP email notifications.

use std::path::Path;

use anyhow::Context;
use lettre::{
    Message, SmtpTransport, Transport,
    message::{Attachment, MultiPart, SinglePart, header::ContentType},
    transport::smtp::authentication::Credentials,
};
use tracing::{debug, info};

use crate::{config::AppConfig, db::Database};

/// Sends a monitoring summary email with the report zip attached when email is enabled.
pub async fn send_summary(
    db: &Database,
    config: &AppConfig,
    batch_id: &str,
    zip_path: &Path,
) -> anyhow::Result<()> {
    if !config.email.enabled {
        debug!("email notification disabled");
        return Ok(());
    }
    info!(
        batch = %batch_id,
        smtp_host = %config.email.smtp_host,
        smtp_port = config.email.smtp_port,
        smtp_security = %config.email.smtp_security,
        from = %config.email.from,
        recipient_count = config.email.to.len(),
        attachment = %zip_path.display(),
        "email notification preparing"
    );
    let status = db.batch_status(Some(batch_id))?;
    let subject = format!(
        "[watcher] batch {} {} alerts={} vulns={}",
        status.batch_id, status.status, status.alerts, status.vulnerabilities
    );
    let body = format!(
        "任务批次: {}\n开始时间: {}\n结束时间: {}\n执行状态: {}\n资产变化/告警: {}\n漏洞列表: {}\n报告附件: {}\n",
        status.batch_id,
        status.started_at,
        status.ended_at.unwrap_or_else(|| "-".to_string()),
        status.status,
        status.alerts,
        status.vulnerabilities,
        zip_path.display()
    );
    let zip_bytes = std::fs::read(zip_path)
        .with_context(|| format!("email attachment read failed: {}", zip_path.display()))?;
    info!(
        batch = %batch_id,
        attachment = %zip_path.display(),
        attachment_bytes = zip_bytes.len(),
        "email attachment loaded"
    );

    let mut builder = Message::builder()
        .from(
            config
                .email
                .from
                .parse()
                .with_context(|| format!("invalid email.from `{}`", config.email.from))?,
        )
        .subject(subject);
    for recipient in &config.email.to {
        builder = builder.to(recipient
            .parse()
            .with_context(|| format!("invalid email recipient `{recipient}`"))?);
    }

    let content_type =
        ContentType::parse("application/zip").context("failed to parse attachment content type")?;
    let email = builder
        .multipart(
            MultiPart::mixed()
                .singlepart(SinglePart::plain(body))
                .singlepart(
                    Attachment::new(
                        zip_path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("watcher-report.zip")
                            .to_string(),
                    )
                    .body(zip_bytes, content_type),
                ),
        )
        .context("failed to build email message")?;

    let credentials =
        Credentials::new(config.email.username.clone(), config.email.password.clone());
    let mailer = smtp_builder(
        &config.email.smtp_host,
        config.email.smtp_port,
        &config.email.smtp_security,
    )?
    .credentials(credentials)
    .build();
    info!(
        batch = %batch_id,
        smtp_host = %config.email.smtp_host,
        smtp_port = config.email.smtp_port,
        smtp_security = %config.email.smtp_security,
        "smtp send starting"
    );
    tokio::task::spawn_blocking(move || mailer.send(&email))
        .await
        .context("smtp send worker join failed")?
        .context("smtp send failed")?;
    info!(batch = %batch_id, "email notification sent");
    Ok(())
}

/// Builds an SMTP transport builder with the correct TLS mode for the configured port.
fn smtp_builder(
    host: &str,
    port: u16,
    security: &str,
) -> anyhow::Result<lettre::transport::smtp::SmtpTransportBuilder> {
    let mode = match security.trim().to_ascii_lowercase().as_str() {
        "auto" => {
            if port == 465 {
                "tls"
            } else {
                "starttls"
            }
        }
        "ssl" | "tls" | "smtps" => "tls",
        "starttls" => "starttls",
        "none" | "plain" => "none",
        other => {
            anyhow::bail!("unsupported smtp_security `{other}`; use auto, tls, starttls, or none")
        }
    };

    let builder = match mode {
        "tls" => SmtpTransport::relay(host)
            .with_context(|| format!("failed to build SMTPS relay for host `{host}`"))?,
        "starttls" => SmtpTransport::starttls_relay(host)
            .with_context(|| format!("failed to build STARTTLS relay for host `{host}`"))?,
        "none" => SmtpTransport::builder_dangerous(host),
        _ => unreachable!("smtp security mode is normalized above"),
    };
    Ok(builder.port(port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_auto_smtp_transport_for_qq_ports() {
        smtp_builder("smtp.qq.com", 465, "auto").unwrap();
        smtp_builder("smtp.qq.com", 587, "auto").unwrap();
        smtp_builder("smtp.qq.com", 587, "starttls").unwrap();
    }

    #[test]
    fn rejects_unknown_smtp_security() {
        assert!(smtp_builder("smtp.qq.com", 587, "magic").is_err());
    }
}
