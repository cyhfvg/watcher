//! Detailed nmap-based service fingerprinting.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures::{StreamExt, stream};
use regex::Regex;
use tokio::{process::Command, time::timeout};
use tracing::{info, warn};

use crate::{
    config::AppConfig,
    db::Database,
    models::{BatchContext, PortAsset},
};

/// 在轻量指纹完成后, 对开放端口运行 nmap 服务识别.
///
/// 配置关闭或没有开放端口时直接返回.
///
/// # 参数
///
/// - `db`: 开放端口和深度指纹结果的数据库句柄.
/// - `config`: 读取 nmap 路径, 超时和并发.
/// - `batch`: 当前监测批次.
///
/// # 返回
///
/// 任务关闭, 无需扫描, 或全部端口处理完成后返回 `Ok(())`.
///
/// # Errors
///
/// 列出开放端口或 nmap 不可用时返回错误. 单个端口失败只记日志.
///
/// # 示例
///
/// ```no_run
/// # use watcher::{config::AppConfig, db::Database, models::BatchContext, monitor::detailed_fingerprint};
/// # async fn demo(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
/// detailed_fingerprint::run(db, config, batch).await?;
/// # Ok(())
/// # }
/// ```
pub async fn run(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
    let detailed = &config.fingerprint.detailed;
    if !detailed.enabled {
        info!(batch = %batch.id, "task6 detailed fingerprint disabled by config");
        return Ok(());
    }

    let ports = db.list_open_ports()?;
    let total_ports = ports.len();
    if ports.is_empty() {
        info!(batch = %batch.id, open_ports = 0, "task6 detailed fingerprint skipped");
        return Ok(());
    }

    info!(
        batch = %batch.id,
        open_ports = total_ports,
        concurrency = detailed.concurrency(),
        timeout_ms = detailed.timeout().as_millis(),
        nmap_path = %detailed.nmap_path,
        "task6 detailed fingerprint preparing nmap"
    );
    ensure_nmap_available(&detailed.nmap_path).await?;
    info!(
        batch = %batch.id,
        nmap_path = %detailed.nmap_path,
        "task6 detailed fingerprint nmap available"
    );

    let db_clone = db.clone();
    let concurrency = detailed.concurrency();
    let progress_counter = Arc::new(AtomicUsize::new(0));
    let completed_ports = Arc::clone(&progress_counter);
    let progress_interval = crate::monitor::progress::scan_progress_interval(total_ports);
    stream::iter(ports)
        .for_each_concurrent(concurrency, move |port| {
            let db = db_clone.clone();
            let batch_id = batch.id.clone();
            let completed_ports = Arc::clone(&completed_ports);
            async move {
                if matches!(db.should_stop_batch(&batch_id), Ok(true)) {
                    completed_ports.fetch_add(1, Ordering::Relaxed);
                    return;
                }

                if let Err(error) = nmap_fingerprint_port(config, &port)
                    .await
                    .and_then(|result| {
                        result.map_or(Ok(()), |result| {
                            db.update_port_detailed_fingerprint(
                                &port.id,
                                result.service.as_deref(),
                                result.fingerprint.as_deref(),
                            )
                        })
                    })
                {
                    warn!(
                        batch = %batch_id,
                        ip = ?port.ip,
                        port = port.port,
                        %error,
                        "task6 detailed fingerprint port failed"
                    );
                }

                let completed = completed_ports.fetch_add(1, Ordering::Relaxed) + 1;
                if crate::monitor::progress::should_log_scan_progress(
                    completed,
                    total_ports,
                    progress_interval,
                ) {
                    info!(
                        batch = %batch_id,
                        progress = %format!("{completed}/{total_ports}"),
                        "task6 detailed fingerprint progress"
                    );
                }
            }
        })
        .await;

    info!(
        batch = %batch.id,
        completed_ports = progress_counter.load(Ordering::Relaxed),
        total_ports,
        "task6 detailed fingerprint all ports processed"
    );

    Ok(())
}

/// 在启动深度指纹任务前确认 nmap 可用.
///
/// # 参数
///
/// - `nmap_path`: nmap 可执行文件路径或命令名.
///
/// # 返回
///
/// `--version` 成功时返回 `Ok(())`.
///
/// # Errors
///
/// 命令不存在, 超时, 或 `--version` 失败时返回错误.
///
/// # 示例
///
/// ```text
/// ensure_nmap_available(&detailed.nmap_path).await?;
/// ```
async fn ensure_nmap_available(nmap_path: &str) -> anyhow::Result<()> {
    let output = timeout(
        Duration::from_secs(5),
        Command::new(nmap_path)
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await?;
    match output {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => anyhow::bail!(
            "detailed fingerprint is enabled but `{nmap_path} --version` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => anyhow::bail!(
            "detailed fingerprint is enabled but nmap was not available at `{nmap_path}`: {error}"
        ),
    }
}

/// 对一个开放 TCP 端口运行 nmap 服务识别.
///
/// # 参数
///
/// - `config`: 读取 nmap 路径和超时.
/// - `port`: 待识别的开放端口.
///
/// # 返回
///
/// 端口没有绑定 IP 时返回 `None`; 否则返回解析出的服务标签和证据.
///
/// # Errors
///
/// nmap 超时, 退出码非零, 或无法读取输出时返回错误.
///
/// # 示例
///
/// ```text
/// let result = nmap_fingerprint_port(config, &port).await?;
/// ```
async fn nmap_fingerprint_port(
    config: &AppConfig,
    port: &PortAsset,
) -> anyhow::Result<Option<NmapFingerprint>> {
    let Some(ip) = &port.ip else {
        return Ok(None);
    };

    let mut command = Command::new(&config.fingerprint.detailed.nmap_path);
    command.args([
        "-sV",
        "--version-light",
        "-Pn",
        "-p",
        &port.port.to_string(),
        "-oX",
        "-",
        ip,
    ]);
    command.kill_on_drop(true);

    let output = timeout(config.fingerprint.detailed.timeout(), command.output()).await??;
    if !output.status.success() {
        anyhow::bail!(
            "nmap exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_nmap_xml(&stdout, port.port))
}

/// Parsed nmap service detection result.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NmapFingerprint {
    /// Service label reported by nmap.
    service: Option<String>,
    /// Human-readable nmap evidence.
    fingerprint: Option<String>,
}

/// 从 nmap XML 中提取指定 TCP 端口的服务标签.
///
/// # 参数
///
/// - `xml`: nmap `-oX -` 输出.
/// - `port`: 目标 TCP 端口.
///
/// # 返回
///
/// 找到对应端口块时返回指纹; 否则 `None`.
///
/// # 示例
///
/// ```text
/// let result = parse_nmap_xml(&stdout, port.port);
/// ```
fn parse_nmap_xml(xml: &str, port: u16) -> Option<NmapFingerprint> {
    let port_block = find_port_block(xml, port)?;
    let state_tag = find_tag(port_block, "state");
    let state = state_tag
        .as_deref()
        .and_then(|tag| attr_value(tag, "state"))
        .unwrap_or_else(|| "unknown".to_string());
    let service_tag = find_tag(port_block, "service");
    let service = service_tag
        .as_deref()
        .and_then(|tag| attr_value(tag, "name"))
        .filter(|value| !value.is_empty());

    let mut parts = vec![format!("nmap_state={state}")];
    if let Some(tag) = service_tag.as_deref() {
        push_attr(&mut parts, "service", tag, "name");
        push_attr(&mut parts, "product", tag, "product");
        push_attr(&mut parts, "version", tag, "version");
        push_attr(&mut parts, "extrainfo", tag, "extrainfo");
        push_attr(&mut parts, "ostype", tag, "ostype");
        push_attr(&mut parts, "conf", tag, "conf");
    }
    if let Some(cpe) = find_cpe(port_block) {
        parts.push(format!("cpe={cpe}"));
    }

    Some(NmapFingerprint {
        service,
        fingerprint: Some(parts.join("; ")),
    })
}

/// 查找指定 TCP 端口的 XML 块.
///
/// # 参数
///
/// - `xml`: 完整 nmap XML.
/// - `port`: 目标端口号.
///
/// # 返回
///
/// 匹配的 `<port ...>...</port>` 片段.
///
/// # 示例
///
/// ```text
/// let block = find_port_block(xml, 22)?;
/// ```
fn find_port_block(xml: &str, port: u16) -> Option<&str> {
    let regex = Regex::new(r#"(?s)<port\b[^>]*>.*?</port>"#).ok()?;
    regex
        .find_iter(xml)
        .map(|matched| matched.as_str())
        .find(|block| {
            attr_value(block, "protocol").as_deref() == Some("tcp")
                && attr_value(block, "portid").as_deref() == Some(&port.to_string())
        })
}

/// 在一小段 nmap XML 中按名字查找单个标签.
///
/// # 参数
///
/// - `block`: 端口 XML 片段.
/// - `name`: 标签名, 例如 `state` 或 `service`.
///
/// # 返回
///
/// 匹配到的起始标签文本.
///
/// # 示例
///
/// ```text
/// let tag = find_tag(port_block, "service");
/// ```
fn find_tag(block: &str, name: &str) -> Option<String> {
    let regex = Regex::new(&format!(r#"<{}\b[^>]*>"#, regex::escape(name))).ok()?;
    regex
        .find(block)
        .map(|matched| matched.as_str().to_string())
}

/// 提取端口块中第一个 CPE 值.
///
/// # 参数
///
/// - `block`: 端口 XML 片段.
///
/// # 返回
///
/// 解码后的 CPE 字符串; 没有或为空时返回 `None`.
///
/// # 示例
///
/// ```text
/// if let Some(cpe) = find_cpe(port_block) { parts.push(format!("cpe={cpe}")); }
/// ```
fn find_cpe(block: &str) -> Option<String> {
    let regex = Regex::new(r#"(?s)<cpe>(.*?)</cpe>"#).ok()?;
    regex
        .captures(block)
        .and_then(|captures| captures.get(1))
        .map(|value| xml_unescape(value.as_str()))
        .filter(|value| !value.is_empty())
}

/// 提取 XML 属性值.
///
/// # 参数
///
/// - `tag`: 标签或属性所在文本.
/// - `name`: 属性名.
///
/// # 返回
///
/// 解码后的属性值.
///
/// # 示例
///
/// ```text
/// let state = attr_value(tag, "state");
/// ```
fn attr_value(tag: &str, name: &str) -> Option<String> {
    let regex = Regex::new(&format!(r#"\b{}\s*=\s*"([^"]*)""#, regex::escape(name))).ok()?;
    regex
        .captures(tag)
        .and_then(|captures| captures.get(1))
        .map(|value| xml_unescape(value.as_str()))
}

/// 当属性存在且非空时, 追加 `label=value` 片段.
///
/// # 参数
///
/// - `parts`: 指纹片段列表.
/// - `label`: 输出标签.
/// - `tag`: 属性所在标签.
/// - `attr`: 属性名.
///
/// # 返回
///
/// 无.
///
/// # 示例
///
/// ```text
/// push_attr(&mut parts, "product", tag, "product");
/// ```
fn push_attr(parts: &mut Vec<String>, label: &str, tag: &str, attr: &str) {
    if let Some(value) = attr_value(tag, attr).filter(|value| !value.is_empty()) {
        parts.push(format!("{label}={value}"));
    }
}

/// 对 nmap 属性 / 文本做最小 XML 实体解码.
///
/// # 参数
///
/// - `value`: 可能包含实体的文本.
///
/// # 返回
///
/// 解码后的字符串.
///
/// # 示例
///
/// ```text
/// let text = xml_unescape(value);
/// ```
fn xml_unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nmap_service_xml() {
        let xml = r#"
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu" extrainfo="protocol 2.0" conf="10"/>
        <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
      </port>
    </ports>
  </host>
</nmaprun>
"#;
        let result = parse_nmap_xml(xml, 22).unwrap();
        assert_eq!(result.service.as_deref(), Some("ssh"));
        let fingerprint = result.fingerprint.unwrap();
        assert!(fingerprint.contains("nmap_state=open"));
        assert!(fingerprint.contains("product=OpenSSH"));
        assert!(fingerprint.contains("cpe=cpe:/a:openbsd:openssh:8.9p1"));
    }

    #[test]
    fn preserves_state_when_service_is_absent() {
        let xml = r#"
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="81">
        <state state="filtered" reason="no-response"/>
      </port>
    </ports>
  </host>
</nmaprun>
"#;
        let result = parse_nmap_xml(xml, 81).unwrap();
        assert_eq!(result.service, None);
        assert_eq!(result.fingerprint.as_deref(), Some("nmap_state=filtered"));
    }
}
