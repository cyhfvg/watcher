//! Helpers for detecting leaked webpack JavaScript source maps.

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

/// Checks whether a webpack JavaScript source map is publicly reachable.
///
/// # Arguments
///
/// - `db`: used to persist vulns and alerts.
/// - `client`: shared HTTP client.
/// - `config`: reads per-target delay and candidate caps.
/// - `batch_id`: current batch id.
/// - `asset`: URL asset to inspect.
///
/// # Returns
///
/// Script-fetch, candidate-check, and finding counts for this URL.
///
/// # Errors
///
/// Returns an error if candidate URLs cannot be collected or vulns / alerts
/// cannot be written. Individual HTTP failures are skipped.
///
/// # Examples
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

/// Collects source-map candidate URLs by fetching a page or JS resource.
///
/// # Arguments
///
/// - `client`: shared HTTP client.
/// - `config`: reads JS-file and map-candidate caps.
/// - `url`: input URL, either `.js` or `.js.map`.
///
/// # Returns
///
/// Candidate map URL set plus the script-fetch count.
///
/// # Errors
///
/// Returns an error if the input URL cannot be parsed. HTTP failures are
/// skipped.
///
/// # Examples
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

/// Returns whether a URL is suitable source-map check input.
///
/// # Arguments
///
/// - `url`: raw URL text.
///
/// # Returns
///
/// `true` when the path ends with `.js` or `.js.map`; `false` if it cannot be
/// parsed.
///
/// # Examples
///
/// ```text
/// if is_sourcemap_input_url(&asset.url) { urls.push(asset); }
/// ```
pub(super) fn is_sourcemap_input_url(url: &str) -> bool {
    Url::parse(url)
        .map(|url| is_javascript_url(&url) || is_sourcemap_url(&url))
        .unwrap_or(false)
}

/// Returns whether the URL is a JavaScript resource, ignoring the query string.
///
/// # Arguments
///
/// - `url`: parsed URL.
///
/// # Returns
///
/// `true` when the path (lowercased) ends with `.js`.
///
/// # Examples
///
/// ```text
/// if is_javascript_url(&url) { /* fetch script */ }
/// ```
fn is_javascript_url(url: &Url) -> bool {
    url.path().to_ascii_lowercase().ends_with(".js")
}

/// Returns whether the URL is a source-map resource, ignoring the query string.
///
/// # Arguments
///
/// - `url`: parsed URL.
///
/// # Returns
///
/// `true` when the path (lowercased) ends with `.js.map`.
///
/// # Examples
///
/// ```text
/// if is_sourcemap_url(&url) { candidates.insert(url.to_string()); }
/// ```
fn is_sourcemap_url(url: &Url) -> bool {
    url.path().to_ascii_lowercase().ends_with(".js.map")
}

/// Infers the conventional `.js.map` sibling URL for a JavaScript resource.
///
/// Query strings identify script variants, not the map file, so they are
/// stripped from the inferred result.
///
/// # Arguments
///
/// - `url`: JavaScript resource URL.
///
/// # Returns
///
/// `.js.map` URL with the query string removed; `None` for a non-JS path.
///
/// # Examples
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

/// Source-map candidates collected from one URL.
#[derive(Debug, Default)]
struct SourcemapCandidates {
    /// Candidate source-map URLs.
    candidates: BTreeSet<String>,
    /// Script URLs seen before rate limiting.
    script_urls_seen: usize,
    /// Script URLs actually fetched after rate limiting.
    script_urls_checked: usize,
}

/// Source-map POC counters for a single URL.
#[derive(Debug, Default)]
pub(super) struct SourcemapScanStats {
    /// Script URLs seen before rate limiting.
    pub(super) script_urls_seen: usize,
    /// Script URLs actually fetched after rate limiting.
    pub(super) script_urls_checked: usize,
    /// Source-map candidates fetched and checked.
    pub(super) map_candidates_checked: usize,
    /// Source-map findings written.
    pub(super) findings: usize,
}

/// Extracts a `sourceMappingURL` marker from JavaScript text.
///
/// # Arguments
///
/// - `body`: JavaScript response-body prefix.
///
/// # Returns
///
/// Relative or absolute map path from the marker; `None` when absent.
///
/// # Examples
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

/// Returns whether the body looks like common source-map JSON.
///
/// # Arguments
///
/// - `body`: HTTP response-body prefix.
///
/// # Returns
///
/// `true` when it contains `version`, `sources`, and either `mappings` or
/// `sourcesContent`.
///
/// # Examples
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

    /// Starts a one-shot fixture that returns JS and then the matching source
    /// map.
    ///
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// Local HTTP URL pointing at `app.js?v=42`.
    ///
    /// # Examples
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
