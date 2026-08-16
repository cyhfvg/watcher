//! Slow web directory enumeration and lightweight page parsing.

use std::{
    collections::BTreeSet,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use futures::{StreamExt, stream};
use regex::Regex;
use reqwest::Client;
use tokio::time::sleep;
use tracing::{info, warn};
use url::Url;

use crate::{
    config::AppConfig,
    db::Database,
    models::{BatchContext, PortAsset},
    monitor::{
        fingerprint::http_client,
        http::{MAX_RESPONSE_BODY_BYTES, response_text_prefix},
        progress::{scan_progress_interval, should_log_scan_progress},
    },
};

static INTERESTING_PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:src|href)\s*=\s*["']([^"']+)["']|["']((?:/[a-zA-Z0-9_./-]+|[a-zA-Z0-9_./-]+\.(?:js|html|json|action|do)))["']"#)
        .expect("static regex must compile")
});

/// 对已识别的 Web 服务枚举路径, 并记录有价值的 URL 资产.
///
/// # 参数
///
/// - `db`: Web 服务, 字典路径和 URL 资产的数据库句柄.
/// - `config`: 读取 HTTP 并发, 路径上限和负向正文标记.
/// - `batch`: 当前监测批次.
///
/// # 返回
///
/// 全部服务处理完成后返回 `Ok(())`.
///
/// # Errors
///
/// 构造 HTTP 客户端, 回放待办, 列出 Web 服务或读取字典失败时返回错误. 单个服务失败只记日志.
///
/// # 示例
///
/// ```no_run
/// # use watcher::{config::AppConfig, db::Database, models::BatchContext, monitor::web_enum};
/// # async fn demo(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
/// web_enum::run(db, config, batch).await?;
/// # Ok(())
/// # }
/// ```
pub async fn run(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
    let client = http_client(config)?;
    replay_pending_work(db, &client, config, batch).await?;

    let services = db.list_web_services()?;
    let dict = db.list_dict_paths(config.web.max_paths_per_service)?;
    let service_count = services.len();
    let dict_path_count = dict.len();
    let concurrency = config.http_concurrency();
    let db_clone = db.clone();
    let started = Instant::now();
    let completed_services = Arc::new(AtomicUsize::new(0));
    let progress_interval = scan_progress_interval(service_count);

    info!(
        concurrency,
        service_count,
        dict_path_count,
        max_js_paths_per_service = config.web.max_js_paths_per_service,
        "web path scan started"
    );

    let scan_completed_services = Arc::clone(&completed_services);
    stream::iter(services)
        .for_each_concurrent(concurrency, move |service| {
            let db = db_clone.clone();
            let client = client.clone();
            let dict = dict.clone();
            let batch_id = batch.id.clone();
            let completed_services = Arc::clone(&scan_completed_services);
            async move {
                if let Err(error) =
                    enumerate_service(&db, &client, config, &batch_id, &service, &dict).await
                {
                    warn!(service = ?service, %error, "web enumeration failed");
                }
                let completed = completed_services.fetch_add(1, Ordering::Relaxed) + 1;
                if should_log_scan_progress(completed, service_count, progress_interval) {
                    info!(
                        completed_services = completed,
                        service_count,
                        progress = %format!("{completed}/{service_count}"),
                        elapsed_ms = started.elapsed().as_millis(),
                        "web path scan progress"
                    );
                }
            }
        })
        .await;

    info!(
        completed_services = completed_services.load(Ordering::Relaxed),
        service_count,
        dict_path_count,
        elapsed_ms = started.elapsed().as_millis(),
        "web path scan finished"
    );
    Ok(())
}

/// 在新工作开始前回放未完成的 Web 枚举 URL.
///
/// # 参数
///
/// - `db`: 待办队列和 URL 资产的数据库句柄.
/// - `client`: 共享 HTTP 客户端.
/// - `config`: 读取每目标延迟和负向标记.
/// - `batch`: 当前监测批次.
///
/// # 返回
///
/// 队列为空或批次被要求停止时返回 `Ok(())`.
///
/// # Errors
///
/// 查询停止标志, 取出 / 完成待办, 或写入 URL 失败时返回错误.
///
/// # 示例
///
/// ```text
/// replay_pending_work(db, &client, config, batch).await?;
/// ```
async fn replay_pending_work(
    db: &Database,
    client: &Client,
    config: &AppConfig,
    batch: &BatchContext,
) -> anyhow::Result<()> {
    loop {
        if db.should_stop_batch(&batch.id)? {
            break;
        }
        let Some(work) = db.take_pending_work("web_enum", 1)?.pop() else {
            break;
        };
        if let Some(result) = fetch_candidate(client, &work.target, config).await?
            && result.score > 0
        {
            db.upsert_url(
                &work.system_id,
                &work.target,
                "discovered",
                Some(result.status),
                result.score,
            )?;
        }
        db.finish_pending_work(&work.id)?;
        sleep(config.per_target_delay()).await;
    }
    Ok(())
}

/// 用字典路径和 JS 发现路径枚举单个 Web 服务.
///
/// # 参数
///
/// - `db`: URL 资产和停止标志的数据库句柄.
/// - `client`: 共享 HTTP 客户端.
/// - `config`: 读取延迟, JS 路径上限和负向标记.
/// - `batch_id`: 当前批次 id.
/// - `service`: 已识别的 Web 端口资产.
/// - `dict`: 本批次使用的路径字典.
///
/// # 返回
///
/// 枚举完成或因停止请求提前退出时返回 `Ok(())`.
///
/// # Errors
///
/// 构造基址, 写 URL / 待办, 或抓取候选失败时返回错误.
///
/// # 示例
///
/// ```text
/// enumerate_service(db, client, config, batch_id, &service, &dict).await?;
/// ```
async fn enumerate_service(
    db: &Database,
    client: &Client,
    config: &AppConfig,
    batch_id: &str,
    service: &PortAsset,
    dict: &[String],
) -> anyhow::Result<()> {
    let bases = service_base_urls(db, service)?;

    let mut js_paths = BTreeSet::new();
    for base in bases {
        if db.should_stop_batch(batch_id)? {
            return Ok(());
        }
        db.upsert_url(&service.system_id, base.as_str(), "discovered", None, 20)?;

        if let Some(result) = fetch_candidate(client, base.as_str(), config).await? {
            db.upsert_url(
                &service.system_id,
                base.as_str(),
                "discovered",
                Some(result.status),
                result.score,
            )?;
            js_paths.extend(extract_interesting_paths(&result.body, &base));
        }

        for path in dict {
            let candidate = base.join(path.trim_start_matches('/'))?;
            if db.should_stop_batch(batch_id)? {
                db.add_pending_work(
                    batch_id,
                    &service.system_id,
                    "web_enum",
                    candidate.as_str(),
                    10,
                )?;
                return Ok(());
            }
            if let Some(result) = fetch_candidate(client, candidate.as_str(), config).await?
                && result.score > 0
            {
                db.upsert_url(
                    &service.system_id,
                    candidate.as_str(),
                    "discovered",
                    Some(result.status),
                    result.score,
                )?;
                if result.status == 200 {
                    js_paths.extend(extract_interesting_paths(&result.body, &candidate));
                }
            }
            sleep(config.per_target_delay()).await;
        }
    }

    for target in js_paths
        .into_iter()
        .take(config.web.max_js_paths_per_service)
    {
        if db.should_stop_batch(batch_id)? {
            db.add_pending_work(batch_id, &service.system_id, "web_enum", &target, 5)?;
            return Ok(());
        }
        if let Some(result) = fetch_candidate(client, &target, config).await?
            && result.score > 0
        {
            db.upsert_url(
                &service.system_id,
                &target,
                "js_discovered",
                Some(result.status),
                result.score,
            )?;
        }
        sleep(config.per_target_delay()).await;
    }

    Ok(())
}

/// HTTP fetch result for an enumeration candidate.
#[derive(Debug)]
struct CandidateResult {
    /// HTTP status code.
    status: u16,
    /// Response body prefix.
    body: String,
    /// Value score; zero means ignore.
    score: i64,
}

/// 抓取候选 URL 并打分, 判断是否值得保留.
///
/// # 参数
///
/// - `client`: 共享 HTTP 客户端.
/// - `url`: 候选绝对 URL.
/// - `config`: 读取负向正文标记.
///
/// # 返回
///
/// 请求失败时返回 `None`; 成功时返回状态, 正文前缀和分数.
///
/// # Errors
///
/// 当前实现把 HTTP 失败视为 `None`, 一般不返回错误.
///
/// # 示例
///
/// ```text
/// if let Some(result) = fetch_candidate(client, url, config).await? { /* upsert */ }
/// ```
async fn fetch_candidate(
    client: &Client,
    url: &str,
    config: &AppConfig,
) -> anyhow::Result<Option<CandidateResult>> {
    let response = match client.get(url).send().await {
        Ok(response) => response,
        Err(_) => return Ok(None),
    };
    let status = response.status().as_u16();
    let body_prefix = response_text_prefix(response, MAX_RESPONSE_BODY_BYTES)
        .await
        .unwrap_or_default();
    let score = value_score(status, &body_prefix, &config.web.negative_body_markers);
    Ok(Some(CandidateResult {
        status,
        body: body_prefix,
        score,
    }))
}

/// 为报告优先级计算价值分; 命中负向标记时为 0.
///
/// # 参数
///
/// - `status`: HTTP 状态码.
/// - `body`: 响应正文前缀.
/// - `negative_markers`: 伪造成功页标记.
///
/// # 返回
///
/// `200 -> 50`, `401/403 -> 80`, 重定向 `30`, `204 -> 20`, 其余或负向命中为 `0`.
///
/// # 示例
///
/// ```text
/// let score = value_score(status, &body, &markers);
/// ```
fn value_score(status: u16, body: &str, negative_markers: &[String]) -> i64 {
    if negative_markers.iter().any(|marker| body.contains(marker)) {
        return 0;
    }
    match status {
        200 => 50,
        401 | 403 => 80,
        301 | 302 | 307 | 308 => 30,
        204 => 20,
        _ => 0,
    }
}

/// 为 `ip:port` 和同系统域名构造 Web 基址.
///
/// # 参数
///
/// - `db`: 用于列出同系统域名.
/// - `service`: Web 端口资产.
///
/// # 返回
///
/// 去重后的基址列表.
///
/// # Errors
///
/// 构造或解析基址失败, 或查询域名失败时返回错误.
///
/// # 示例
///
/// ```text
/// let bases = service_base_urls(db, service)?;
/// ```
fn service_base_urls(db: &Database, service: &PortAsset) -> anyhow::Result<Vec<Url>> {
    let mut values = BTreeSet::new();
    let scheme = service.scheme.as_deref().unwrap_or("http");
    let ip = service.ip.as_deref().unwrap_or("127.0.0.1");
    values.insert(host_base_url(scheme, ip, service.port)?);
    for domain in db.list_domains_for_system(&service.system_id)? {
        values.insert(host_base_url(scheme, &domain.name, service.port)?);
    }
    Ok(values.into_iter().collect())
}

/// 为单个 host 和协议 / 端口组合构造基址.
///
/// 默认端口 `80` / `443` 会从 URL 中省略.
///
/// # 参数
///
/// - `scheme`: `http` 或 `https`.
/// - `host`: IP 或域名.
/// - `port`: TCP 端口.
///
/// # 返回
///
/// 以 `/` 结尾的基址.
///
/// # Errors
///
/// URL 无法解析时返回错误.
///
/// # 示例
///
/// ```text
/// let url = host_base_url("http", "example.com", 80)?;
/// ```
fn host_base_url(scheme: &str, host: &str, port: u16) -> anyhow::Result<Url> {
    let text = if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
        format!("{scheme}://{host}/")
    } else {
        format!("{scheme}://{host}:{port}/")
    };
    Ok(Url::parse(&text)?)
}

/// 从 HTML / JS 路径引用中提取绝对 URL.
///
/// # 参数
///
/// - `body`: 页面或脚本正文前缀.
/// - `base`: 用于解析相对路径的基址.
///
/// # 返回
///
/// 去重后的 HTTP(S) URL 集合; 忽略 `javascript:` 和锚点.
///
/// # 示例
///
/// ```text
/// let paths = extract_interesting_paths(&body, &base);
/// ```
fn extract_interesting_paths(body: &str, base: &Url) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    for capture in INTERESTING_PATH_REGEX.captures_iter(body) {
        let candidate = capture
            .get(1)
            .or_else(|| capture.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");
        if candidate.starts_with("javascript:") || candidate.starts_with('#') {
            continue;
        }
        if let Ok(url) = base.join(candidate)
            && url.scheme().starts_with("http")
        {
            values.insert(url.to_string());
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_fake_gateway_200() {
        let markers = vec!["接口不存在".to_string(), "code=404".to_string()];
        assert_eq!(value_score(200, "xxx接口不存在，code=404", &markers), 0);
        assert_eq!(value_score(403, "forbidden", &markers), 80);
    }

    #[test]
    fn builds_host_base_urls_with_default_port_elision() {
        assert_eq!(
            host_base_url("http", "example.com", 80)
                .unwrap()
                .to_string(),
            "http://example.com/"
        );
        assert_eq!(
            host_base_url("https", "example.com", 8443)
                .unwrap()
                .to_string(),
            "https://example.com:8443/"
        );
    }
}
