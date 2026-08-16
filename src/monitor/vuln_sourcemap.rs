//! webpack JavaScript source map 泄露检测辅助.

use std::{collections::BTreeSet, sync::LazyLock};

use regex::Regex;
use reqwest::Client;
use tokio::time::sleep;
use url::Url;

use crate::{
    config::AppConfig,
    db::Database,
    models::UrlAsset,
    monitor::http::{MAX_RESPONSE_BODY_BYTES, response_text_prefix},
};

static SOURCE_MAPPING_URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)//[#@]\s*sourceMappingURL=([^\s]+)"#).expect("static regex must compile")
});

/// 检查 webpack JavaScript source map 是否对外可访问.
///
/// # 参数
///
/// - `db`: 用于写入漏洞和告警.
/// - `client`: 共享 HTTP 客户端.
/// - `config`: 读取每目标延迟和候选数量上限.
/// - `batch_id`: 当前批次 id.
/// - `asset`: 待检查的 URL 资产.
///
/// # 返回
///
/// 该 URL 的脚本抓取, 候选检查和发现计数.
///
/// # Errors
///
/// 收集候选 URL 或写入漏洞 / 告警失败时返回错误. 单次 HTTP 失败会被跳过.
///
/// # 示例
///
/// ```text
/// let stats = check_sourcemap(db, client, config, batch_id, asset).await?;
/// ```
pub(super) async fn check_sourcemap(
    db: &Database,
    client: &Client,
    config: &AppConfig,
    batch_id: &str,
    asset: &UrlAsset,
) -> anyhow::Result<SourcemapScanStats> {
    let collection = collect_sourcemap_candidates(client, config, &asset.url).await?;
    let mut stats = SourcemapScanStats {
        script_urls_seen: collection.script_urls_seen,
        script_urls_checked: collection.script_urls_checked,
        ..SourcemapScanStats::default()
    };
    let candidates: Vec<String> = collection
        .candidates
        .into_iter()
        .take(
            config
                .pocs
                .webpack_sourcemap_disclosure
                .max_map_candidates_per_url(),
        )
        .collect();
    for map_url in candidates {
        sleep(config.per_target_delay()).await;
        stats.map_candidates_checked += 1;
        let response = match client.get(&map_url).send().await {
            Ok(response) => response,
            Err(_) => continue,
        };
        if !response.status().is_success() {
            continue;
        }
        let body = response_text_prefix(response, MAX_RESPONSE_BODY_BYTES)
            .await
            .unwrap_or_default();
        if looks_like_sourcemap(&body) {
            stats.findings += 1;
            db.add_vulnerability(
                batch_id,
                &asset.system_id,
                &map_url,
                "webpack_sourcemap_disclosure",
                "medium",
                "JavaScript source map file is accessible",
            )?;
            db.add_alert(
                batch_id,
                Some(&asset.system_id),
                "vulnerability",
                "medium",
                &map_url,
                None,
                Some("webpack_sourcemap_disclosure"),
                None,
            )?;
        }
    }
    Ok(stats)
}

/// 通过抓取页面或 JS 资源收集 source map 候选 URL.
///
/// # 参数
///
/// - `client`: 共享 HTTP 客户端.
/// - `config`: 读取 JS 文件和 map 候选上限.
/// - `url`: 输入 URL, 可以是 `.js` 或 `.js.map`.
///
/// # 返回
///
/// 候选 map URL 集合以及脚本抓取计数.
///
/// # Errors
///
/// 输入 URL 无法解析时返回错误. HTTP 失败会被跳过.
///
/// # 示例
///
/// ```text
/// let collection = collect_sourcemap_candidates(client, config, url).await?;
/// ```
async fn collect_sourcemap_candidates(
    client: &Client,
    config: &AppConfig,
    url: &str,
) -> anyhow::Result<SourcemapCandidates> {
    let base = Url::parse(url)?;
    let mut candidates = BTreeSet::new();
    if is_sourcemap_url(&base) {
        candidates.insert(url.to_string());
        return Ok(SourcemapCandidates {
            candidates,
            script_urls_seen: 0,
            script_urls_checked: 0,
        });
    }

    if !is_javascript_url(&base) {
        return Ok(SourcemapCandidates::default());
    }

    let js_urls = BTreeSet::from([url.to_string()]);
    let script_urls_seen = 1;

    let mut script_urls_checked = 0usize;
    for js_url in js_urls.into_iter().take(
        config
            .pocs
            .webpack_sourcemap_disclosure
            .max_js_files_per_url(),
    ) {
        sleep(config.per_target_delay()).await;
        script_urls_checked += 1;
        let js_body = match client.get(&js_url).send().await {
            Ok(response) => response_text_prefix(response, MAX_RESPONSE_BODY_BYTES)
                .await
                .unwrap_or_default(),
            Err(_) => continue,
        };
        if let Some(marker) = source_mapping_url(&js_body)
            && let Ok(js_base) = Url::parse(&js_url)
            && let Ok(map_url) = js_base.join(&marker)
        {
            candidates.insert(map_url.to_string());
        }
        if let Ok(js_base) = Url::parse(&js_url)
            && let Some(map_url) = conventional_sourcemap_url(&js_base)
        {
            candidates.insert(map_url);
        }
        if candidates.len()
            >= config
                .pocs
                .webpack_sourcemap_disclosure
                .max_map_candidates_per_url()
        {
            break;
        }
    }

    Ok(SourcemapCandidates {
        candidates,
        script_urls_seen,
        script_urls_checked,
    })
}

/// 判断 URL 是否适合作为 source map 检查输入.
///
/// # 参数
///
/// - `url`: 原始 URL 文本.
///
/// # 返回
///
/// 路径以 `.js` 或 `.js.map` 结尾时返回 `true`; 无法解析时返回 `false`.
///
/// # 示例
///
/// ```text
/// if is_sourcemap_input_url(&asset.url) { urls.push(asset); }
/// ```
pub(super) fn is_sourcemap_input_url(url: &str) -> bool {
    Url::parse(url)
        .map(|url| is_javascript_url(&url) || is_sourcemap_url(&url))
        .unwrap_or(false)
}

/// 判断是否为 JavaScript 资源 URL, 忽略查询串.
///
/// # 参数
///
/// - `url`: 已解析的 URL.
///
/// # 返回
///
/// 路径(小写)以 `.js` 结尾时返回 `true`.
///
/// # 示例
///
/// ```text
/// if is_javascript_url(&url) { /* fetch script */ }
/// ```
fn is_javascript_url(url: &Url) -> bool {
    url.path().to_ascii_lowercase().ends_with(".js")
}

/// 判断是否为 source map 资源 URL, 忽略查询串.
///
/// # 参数
///
/// - `url`: 已解析的 URL.
///
/// # 返回
///
/// 路径(小写)以 `.js.map` 结尾时返回 `true`.
///
/// # 示例
///
/// ```text
/// if is_sourcemap_url(&url) { candidates.insert(url.to_string()); }
/// ```
fn is_sourcemap_url(url: &Url) -> bool {
    url.path().to_ascii_lowercase().ends_with(".js.map")
}

/// 推断 JavaScript 资源对应的常规 `.js.map` 兄弟 URL.
///
/// 查询串标识脚本变体而不是 map 文件, 因此会从推断结果中去掉.
///
/// # 参数
///
/// - `url`: JavaScript 资源 URL.
///
/// # 返回
///
/// 去掉查询串后的 `.js.map` URL; 非 JS 路径返回 `None`.
///
/// # 示例
///
/// ```text
/// if let Some(map_url) = conventional_sourcemap_url(&js_base) {
///     candidates.insert(map_url);
/// }
/// ```
fn conventional_sourcemap_url(url: &Url) -> Option<String> {
    if !is_javascript_url(url) {
        return None;
    }
    let mut map_url = url.clone();
    map_url.set_path(&format!("{}.map", url.path()));
    map_url.set_query(None);
    Some(map_url.to_string())
}

/// 从一个 URL 收集到的 source map 候选.
#[derive(Debug, Default)]
struct SourcemapCandidates {
    /// 候选 source map URL.
    candidates: BTreeSet<String>,
    /// 限流前看到的脚本 URL 数.
    script_urls_seen: usize,
    /// 限流后实际抓取的脚本 URL 数.
    script_urls_checked: usize,
}

/// 单条 URL 的 source map POC 计数.
#[derive(Debug, Default)]
pub(super) struct SourcemapScanStats {
    /// 限流前看到的脚本 URL 数.
    pub(super) script_urls_seen: usize,
    /// 限流后实际抓取的脚本 URL 数.
    pub(super) script_urls_checked: usize,
    /// 已抓取并检查的 source map 候选数.
    pub(super) map_candidates_checked: usize,
    /// 写入的 source map 发现数.
    pub(super) findings: usize,
}

/// 从 JavaScript 文本中提取 `sourceMappingURL` 标记.
///
/// # 参数
///
/// - `body`: JavaScript 响应正文前缀.
///
/// # 返回
///
/// 标记中的相对或绝对 map 路径; 没有标记时返回 `None`.
///
/// # 示例
///
/// ```text
/// if let Some(marker) = source_mapping_url(&js_body) { /* join */ }
/// ```
fn source_mapping_url(body: &str) -> Option<String> {
    SOURCE_MAPPING_URL_REGEX
        .captures(body)
        .and_then(|capture| capture.get(1))
        .map(|m| m.as_str().trim().to_string())
}

/// 判断正文是否具备常见 source map JSON 形状.
///
/// # 参数
///
/// - `body`: HTTP 响应正文前缀.
///
/// # 返回
///
/// 同时包含 `version`, `sources`, 以及 `mappings` 或 `sourcesContent` 时返回 `true`.
///
/// # 示例
///
/// ```text
/// if looks_like_sourcemap(&body) { /* persist finding */ }
/// ```
fn looks_like_sourcemap(body: &str) -> bool {
    body.contains("\"version\"")
        && body.contains("\"sources\"")
        && (body.contains("\"mappings\"") || body.contains("\"sourcesContent\""))
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{config::AppConfig, db::Database, monitor::fingerprint::http_client};

    /// 启动一次性 fixture, 依次返回 JS 和对应 source map.
    ///
    /// # 参数
    ///
    /// 无.
    ///
    /// # 返回
    ///
    /// 指向 `app.js?v=42` 的本地 HTTP URL.
    ///
    /// # 示例
    ///
    /// ```text
    /// let url = serve_sourcemap_fixture().await;
    /// ```
    async fn serve_sourcemap_fixture() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 1024];
                let size = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..size]);
                let body = if request.starts_with("GET /assets/app.js?") {
                    "console.log(1);\n//# sourceMappingURL=app.js.map"
                } else {
                    r#"{"version":3,"sources":["app.ts"],"mappings":"AAAA"}"#
                };
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                stream.write_all(body.as_bytes()).await.unwrap();
            }
        });
        format!("http://{address}/assets/app.js?v=42")
    }

    #[test]
    fn extracts_source_mapping_marker() {
        assert_eq!(
            source_mapping_url("console.log(1);\n//# sourceMappingURL=app.js.map"),
            Some("app.js.map".to_string())
        );
    }

    #[test]
    fn detects_sourcemap_shape() {
        assert!(looks_like_sourcemap(
            r#"{"version":3,"sources":["a.js"],"mappings":"AAAA"}"#
        ));
    }

    #[test]
    fn identifies_sourcemap_input_urls() {
        assert!(is_sourcemap_input_url("https://example.com/app.js"));
        assert!(is_sourcemap_input_url("https://example.com/app.js?v=1"));
        assert!(is_sourcemap_input_url("https://example.com/app.js.map"));
        assert!(!is_sourcemap_input_url("https://example.com/"));
        assert!(!is_sourcemap_input_url("not a url"));
    }

    #[test]
    fn infers_conventional_sourcemap_url_without_query_string() {
        let asset = Url::parse("https://example.com/assets/app.js?v=42").unwrap();

        assert_eq!(
            conventional_sourcemap_url(&asset).as_deref(),
            Some("https://example.com/assets/app.js.map")
        );
    }

    #[tokio::test]
    async fn check_sourcemap_persists_a_finding_and_alert() {
        let directory = tempfile::tempdir().unwrap();
        let db = Database::open(&directory.path().join("watcher.db")).unwrap();
        db.migrate().unwrap();
        let system_id = db.upsert_system("core").unwrap();
        let batch = db.create_batch().unwrap();
        let mut config =
            AppConfig::default_with_path(directory.path().join("watcher.yml")).unwrap();
        config.probe.per_target_delay_ms = 0;
        config
            .pocs
            .webpack_sourcemap_disclosure
            .max_map_candidates_per_url = 1;
        let client = http_client(&config).unwrap();
        let url = serve_sourcemap_fixture().await;
        let asset = UrlAsset {
            id: "asset-1".to_string(),
            system_id,
            system_name: "core".to_string(),
            url,
            source: "discovered".to_string(),
            status_code: Some(200),
            value_score: 50,
            is_baseline: false,
        };

        let stats = check_sourcemap(&db, &client, &config, &batch.id, &asset)
            .await
            .unwrap();

        assert_eq!(stats.map_candidates_checked, 1);
        assert_eq!(stats.findings, 1);
        assert_eq!(db.list_vulnerabilities(&batch.id).unwrap().len(), 1);
        assert_eq!(db.list_alerts(&batch.id).unwrap().len(), 1);
    }
}
