//! Service fingerprinting.

use std::time::Duration;

use futures::{StreamExt, stream};
use reqwest::Client;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tracing::warn;

use crate::{
    config::AppConfig,
    db::Database,
    models::{BatchContext, PortAsset},
};

/// Fingerprints all open ports after port scanning completes.
pub async fn run(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
    let ports = db.list_open_ports()?;
    let client = http_client(config)?;
    let concurrency = config.probe.concurrency.max(1);
    let db_clone = db.clone();

    stream::iter(ports)
        .for_each_concurrent(concurrency, move |port| {
            let db = db_clone.clone();
            let client = client.clone();
            let batch_id = batch.id.clone();
            async move {
                if matches!(db.should_stop_batch(&batch_id), Ok(true)) {
                    return;
                }
                match fingerprint_port(&client, &port, config.http_timeout()).await {
                    Ok(result) => {
                        if let Err(error) = db.update_port_fingerprint(
                            &port.id,
                            result.service.as_deref(),
                            result.fingerprint.as_deref(),
                            result.is_web,
                            result.scheme.as_deref(),
                        ) {
                            warn!(%error, "failed to update fingerprint");
                        }
                    }
                    Err(error) => warn!(port = %port.port, %error, "fingerprint failed"),
                }
            }
        })
        .await;

    Ok(())
}

/// Creates a reqwest client using rustls and permissive cert handling for monitoring.
pub fn http_client(config: &AppConfig) -> anyhow::Result<Client> {
    Ok(Client::builder()
        .timeout(config.http_timeout())
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("watcher/0.1")
        .build()?)
}

/// Fingerprint result for one port.
#[derive(Debug, Clone)]
struct FingerprintResult {
    /// Service label.
    service: Option<String>,
    /// Human-readable fingerprint.
    fingerprint: Option<String>,
    /// Whether the service is HTTP(S).
    is_web: bool,
    /// Web scheme.
    scheme: Option<String>,
}

/// Attempts HTTP(S) probing first, then falls back to a tiny banner grab.
async fn fingerprint_port(
    client: &Client,
    port: &PortAsset,
    timeout_duration: Duration,
) -> anyhow::Result<FingerprintResult> {
    let ip = match &port.ip {
        Some(ip) => ip,
        None => {
            return Ok(FingerprintResult {
                service: Some("tcp".to_string()),
                fingerprint: None,
                is_web: false,
                scheme: None,
            });
        }
    };

    for scheme in preferred_schemes(port.port) {
        let url = format!("{scheme}://{ip}:{}", port.port);
        if let Ok(response) = client.get(&url).send().await {
            let status = response.status().as_u16();
            let server = response
                .headers()
                .get(reqwest::header::SERVER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            let fingerprint = if server.is_empty() {
                format!("http_status={status}")
            } else {
                format!("http_status={status}; server={server}")
            };
            return Ok(FingerprintResult {
                service: Some("web".to_string()),
                fingerprint: Some(fingerprint),
                is_web: true,
                scheme: Some(scheme.to_string()),
            });
        }
    }

    let banner = grab_banner(ip, port.port, timeout_duration)
        .await
        .unwrap_or_default();
    Ok(FingerprintResult {
        service: Some(classify_banner(&banner).to_string()),
        fingerprint: (!banner.is_empty()).then_some(banner),
        is_web: false,
        scheme: None,
    })
}

/// Returns a scheme preference for well-known web ports.
fn preferred_schemes(port: u16) -> Vec<&'static str> {
    match port {
        443 | 8443 => vec!["https", "http"],
        _ => vec!["http", "https"],
    }
}

/// Reads a small service banner.
async fn grab_banner(ip: &str, port: u16, timeout_duration: Duration) -> anyhow::Result<String> {
    let mut stream = timeout(timeout_duration, TcpStream::connect((ip, port))).await??;
    let _ = stream.write_all(b"\r\n").await;
    let mut buffer = vec![0u8; 256];
    let size = timeout(timeout_duration, stream.read(&mut buffer)).await??;
    Ok(String::from_utf8_lossy(&buffer[..size]).trim().to_string())
}

/// Maps a banner into a conservative service label.
fn classify_banner(banner: &str) -> &'static str {
    let lower = banner.to_ascii_lowercase();
    if lower.contains("ssh") {
        "ssh"
    } else if lower.contains("smtp") {
        "smtp"
    } else if lower.contains("ftp") {
        "ftp"
    } else {
        "tcp"
    }
}
