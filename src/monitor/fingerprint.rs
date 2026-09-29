//! Service fingerprinting.

use std::{sync::Arc, time::Duration};

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
    monitor::rate_limit::TokenBucket,
};

/// After port scanning, run lightweight fingerprinting on every open port.
///
/// # Arguments
///
/// - `db`: database handle for open ports and fingerprint results.
/// - `config`: reads HTTP timeout and concurrency.
/// - `batch`: current monitoring batch.
///
/// # Returns
///
/// `Ok(())` after every port has been processed.
///
/// # Errors
///
/// Returns an error if open ports cannot be listed or the HTTP client cannot
/// be built. Per-port failures are logged only.
///
/// # Examples
///
/// ```no_run
/// # use watcher::{config::AppConfig, db::Database, models::BatchContext, monitor::fingerprint};
/// # async fn demo(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
/// fingerprint::run(db, config, batch).await?;
/// # Ok(())
/// # }
/// ```
pub async fn run(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
    let ports = db.list_open_ports()?;
    let client = http_client(config)?;
    let concurrency = config.http_concurrency();
    let db_clone = db.clone();
    let limiter = Arc::new(TokenBucket::new(config.per_target_delay(), 1));

    stream::iter(ports)
        .for_each_concurrent(concurrency, move |port| {
            let db = db_clone.clone();
            let client = client.clone();
            let batch_id = batch.id.clone();
            let limiter = Arc::clone(&limiter);
            async move {
                if matches!(db.should_stop_batch(&batch_id), Ok(true)) {
                    return;
                }
                if let Some(ip) = &port.ip {
                    limiter.acquire(ip).await;
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

/// Builds a monitoring reqwest client: rustls, ignore cert errors, limited
/// redirects.
///
/// # Arguments
///
/// - `config`: reads HTTP timeout.
///
/// # Returns
///
/// Reusable [`Client`].
///
/// # Errors
///
/// Returns an error if the reqwest client cannot be built.
///
/// # Examples
///
/// ```no_run
/// # use watcher::{config::AppConfig, monitor::fingerprint};
/// # fn demo(config: &AppConfig) -> anyhow::Result<()> {
/// let _client = fingerprint::http_client(config)?;
/// # Ok(())
/// # }
/// ```
pub fn http_client(config: &AppConfig) -> anyhow::Result<Client> {
    build_http_client(config, true)
}

/// Builds the enumeration client. Redirects are not followed so the first hop is scored.
///
/// # Arguments
/// - `config`: reads the HTTP timeout.
///
/// # Returns
/// Reqwest client that returns 3xx responses to the caller.
///
/// # Errors
/// Returns an error if the client cannot be built.
///
/// # Examples
/// ```text
/// let client = enumeration_client(config)?;
/// ```
pub fn enumeration_client(config: &AppConfig) -> anyhow::Result<Client> {
    build_http_client(config, false)
}

fn build_http_client(config: &AppConfig, follow_redirects: bool) -> anyhow::Result<Client> {
    let redirects = if follow_redirects {
        reqwest::redirect::Policy::limited(5)
    } else {
        reqwest::redirect::Policy::none()
    };
    Ok(Client::builder()
        .timeout(config.http_timeout())
        .connect_timeout(config.connect_timeout().min(config.http_timeout()))
        .pool_max_idle_per_host(2)
        .danger_accept_invalid_certs(true)
        .redirect(redirects)
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

/// Tries HTTP(S) probing first, then grabs a short banner on failure.
///
/// # Arguments
///
/// - `client`: shared HTTP client.
/// - `port`: open port to identify.
/// - `timeout_duration`: banner grab timeout.
///
/// # Returns
///
/// Service label, fingerprint text, and whether the port looks like Web.
///
/// # Errors
///
/// The current implementation degrades HTTP and banner failures and usually
/// returns a conservative result instead of an error.
///
/// # Examples
///
/// ```text
/// let result = fingerprint_port(client, &port, timeout).await?;
/// ```
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
            if !looks_like_web(&response) {
                drop(response);
                continue;
            }
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
            drop(response);
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

/// Returns the preferred probe scheme order for common Web ports.
///
/// # Arguments
///
/// - `port`: TCP port number.
///
/// # Returns
///
/// `443` / `8443` prefer `https`; everything else prefers `http`.
///
/// # Examples
///
/// ```text
/// for scheme in preferred_schemes(port.port) { /* probe */ }
/// ```
fn preferred_schemes(port: u16) -> &'static [&'static str] {
    match port {
        443 | 8443 => &["https"],
        _ => &["http"],
    }
}

fn looks_like_web(response: &reqwest::Response) -> bool {
    let headers = response.headers();
    let server = headers
        .get(reqwest::header::SERVER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !server.is_empty() {
        return true;
    }
    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    content_type.contains("text/html")
        || content_type.contains("application/xhtml")
        || content_type.contains("application/json")
        || content_type.contains("javascript")
        || content_type.contains("text/xml")
}

/// Reads a short service banner.
///
/// # Arguments
///
/// - `ip`: target IP.
/// - `port`: target port.
/// - `timeout_duration`: connect and read timeout.
///
/// # Returns
///
/// Banner text with surrounding whitespace removed.
///
/// # Errors
///
/// Returns an error if connect, probe write, or read times out / fails.
///
/// # Examples
///
/// ```text
/// let banner = grab_banner(ip, port, timeout).await.unwrap_or_default();
/// ```
async fn grab_banner(ip: &str, port: u16, timeout_duration: Duration) -> anyhow::Result<String> {
    let mut stream = timeout(timeout_duration, TcpStream::connect((ip, port))).await??;
    let _ = stream.write_all(b"\r\n").await;
    let mut buffer = vec![0u8; 256];
    let size = timeout(timeout_duration, stream.read(&mut buffer)).await??;
    Ok(String::from_utf8_lossy(&buffer[..size]).trim().to_string())
}

/// Maps a banner to a conservative service label.
///
/// # Arguments
///
/// - `banner`: captured banner text.
///
/// # Returns
///
/// `ssh` / `smtp` / `ftp`, or `tcp` when unrecognized.
///
/// # Examples
///
/// ```text
/// let service = classify_banner(&banner);
/// ```
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
