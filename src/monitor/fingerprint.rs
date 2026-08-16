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

/// 在端口扫描完成后对全部开放端口做轻量指纹识别.
///
/// # 参数
///
/// - `db`: 开放端口和指纹结果的数据库句柄.
/// - `config`: 读取 HTTP 超时和并发.
/// - `batch`: 当前监测批次.
///
/// # 返回
///
/// 全部端口处理完成后返回 `Ok(())`.
///
/// # Errors
///
/// 列出开放端口或构造 HTTP 客户端失败时返回错误. 单个端口失败只记日志.
///
/// # 示例
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

/// 构造监测用 reqwest 客户端: rustls, 忽略证书错误, 有限重定向.
///
/// # 参数
///
/// - `config`: 读取 HTTP 超时.
///
/// # 返回
///
/// 可复用的 [`Client`].
///
/// # Errors
///
/// reqwest 客户端构建失败时返回错误.
///
/// # 示例
///
/// ```no_run
/// # use watcher::{config::AppConfig, monitor::fingerprint};
/// # fn demo(config: &AppConfig) -> anyhow::Result<()> {
/// let _client = fingerprint::http_client(config)?;
/// # Ok(())
/// # }
/// ```
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

/// 先尝试 HTTP(S) 探测, 失败再抓一小段 banner.
///
/// # 参数
///
/// - `client`: 共享 HTTP 客户端.
/// - `port`: 待识别的开放端口.
/// - `timeout_duration`: banner 抓取超时.
///
/// # 返回
///
/// 服务标签, 指纹文本, 以及是否为 Web.
///
/// # Errors
///
/// 当前实现把 HTTP 和 banner 失败都降级处理, 一般返回保守结果而不是错误.
///
/// # 示例
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

/// 为常见 Web 端口返回优先探测的协议顺序.
///
/// # 参数
///
/// - `port`: TCP 端口号.
///
/// # 返回
///
/// `443` / `8443` 优先 `https`; 其余优先 `http`.
///
/// # 示例
///
/// ```text
/// for scheme in preferred_schemes(port.port) { /* probe */ }
/// ```
fn preferred_schemes(port: u16) -> Vec<&'static str> {
    match port {
        443 | 8443 => vec!["https", "http"],
        _ => vec!["http", "https"],
    }
}

/// 读取一小段服务 banner.
///
/// # 参数
///
/// - `ip`: 目标 IP.
/// - `port`: 目标端口.
/// - `timeout_duration`: 连接和读取超时.
///
/// # 返回
///
/// 去掉空白后的 banner 文本.
///
/// # Errors
///
/// 连接, 写入探测字节或读取超时 / 失败时返回错误.
///
/// # 示例
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

/// 把 banner 映射为保守的服务标签.
///
/// # 参数
///
/// - `banner`: 抓到的 banner 文本.
///
/// # 返回
///
/// `ssh` / `smtp` / `ftp`, 无法识别时返回 `tcp`.
///
/// # 示例
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
