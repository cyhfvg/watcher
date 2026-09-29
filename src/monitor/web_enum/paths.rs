//! URL construction, response scoring, and page-path extraction.

use std::collections::BTreeSet;

use anyhow::Context;
use reqwest::Client;
use url::Url;

use crate::{
    config::AppConfig,
    db::Database,
    models::PortAsset,
    monitor::http::{MAX_RESPONSE_BODY_BYTES, response_text_prefix},
};

use super::INTERESTING_PATH_REGEX;

/// HTTP fetch result for an enumeration candidate.
#[derive(Debug)]
pub(super) struct CandidateResult {
    /// HTTP status code.
    pub(super) status: u16,
    /// Response-body prefix used for scoring and path extraction.
    pub(super) body: String,
    /// Report priority. `0` means the URL is not worth keeping.
    pub(super) score: i64,
}

/// Fetches a candidate URL and scores whether it is worth keeping.
///
/// # Arguments
///
/// - `client`: shared HTTP client.
/// - `url`: candidate absolute URL.
/// - `config`: reads negative body markers.
///
/// # Returns
///
/// `None` when the request fails; otherwise status, body prefix, and score.
///
/// # Errors
///
/// Returns an error when the HTTP request fails before a response. A received
/// response, including 404, is `Ok(Some(...))`. Body-read failures become an
/// empty prefix instead of an error.
///
/// # Examples
///
/// ```text
/// if let Some(result) = fetch_candidate(client, url, config).await? { /* upsert */ }
/// ```
pub(super) async fn fetch_candidate(
    client: &Client,
    url: &str,
    config: &AppConfig,
) -> anyhow::Result<Option<CandidateResult>> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("web enumeration fetch failed for {url}"))?;
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

/// Computes a report-priority value score; negative-marker hits score 0.
///
/// # Arguments
///
/// - `status`: HTTP status code.
/// - `body`: response-body prefix.
/// - `negative_markers`: fake-success page markers.
///
/// # Returns
///
/// `200 -> 50`, `401/403 -> 80`, redirects `30`, `204 -> 20`, otherwise or on
/// a negative hit `0`.
///
/// # Examples
///
/// ```text
/// let score = value_score(status, &body, &markers);
/// ```
fn value_score(status: u16, body: &str, negative_markers: &[String]) -> i64 {
    const MIN_MARKER_LEN: usize = 4;
    let lowered_markers: Vec<String> = negative_markers
        .iter()
        .filter(|marker| marker.chars().count() >= MIN_MARKER_LEN)
        .map(|marker| marker.to_ascii_lowercase())
        .collect();
    if !lowered_markers.is_empty() {
        let lowered_body = body.to_ascii_lowercase();
        if lowered_markers
            .iter()
            .any(|marker| lowered_body.contains(marker.as_str()))
        {
            return 0;
        }
    }
    match status {
        200 => 50,
        401 | 403 => 20,
        301 | 302 | 303 | 307 | 308 => 30,
        204 => 20,
        _ => 0,
    }
}

/// Builds Web base URLs for `ip:port` and same-system domains.
///
/// # Arguments
///
/// - `db`: used to list same-system domains.
/// - `service`: Web port asset.
///
/// # Returns
///
/// Deduplicated base-URL list.
///
/// # Errors
///
/// Returns an error if a base URL cannot be built or parsed, or domains cannot
/// be queried.
///
/// # Examples
///
/// ```text
/// let bases = service_base_urls(db, service)?;
/// ```
pub(super) fn service_base_urls(db: &Database, service: &PortAsset) -> anyhow::Result<Vec<Url>> {
    let Some(ip) = service.ip.as_deref().filter(|ip| !ip.is_empty()) else {
        return Ok(Vec::new());
    };
    let mut values = BTreeSet::new();
    let scheme = service.scheme.as_deref().unwrap_or("http");
    values.insert(host_base_url(scheme, ip, service.port)?);
    for domain in db.list_domains_for_system(&service.system_id)? {
        if domain
            .bind_ip
            .as_deref()
            .is_some_and(|bind| bind.split(',').any(|part| part.trim() == ip))
        {
            values.insert(host_base_url(scheme, &domain.name, service.port)?);
        }
    }
    Ok(values.into_iter().collect())
}

/// Builds a base URL for one host and scheme / port combination.
///
/// Default ports `80` / `443` are omitted from the URL.
///
/// # Arguments
///
/// - `scheme`: `http` or `https`.
/// - `host`: IP or domain.
/// - `port`: TCP port.
///
/// # Returns
///
/// Base URL ending with `/`.
///
/// # Errors
///
/// Returns an error if the URL cannot be parsed.
///
/// # Examples
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

/// Extracts absolute URLs from HTML / JS path references.
///
/// # Arguments
///
/// - `body`: page or script body prefix.
/// - `base`: base URL used to resolve relative paths.
///
/// # Returns
///
/// Deduplicated HTTP(S) URL set; `javascript:` and anchors are ignored.
///
/// # Examples
///
/// ```text
/// let paths = extract_interesting_paths(&body, &base);
/// ```
pub(super) fn extract_interesting_paths(body: &str, base: &Url) -> BTreeSet<String> {
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
            && is_same_origin_script(&url, base)
        {
            values.insert(url.to_string());
        }
    }
    values
}

/// Returns whether `url` is an HTTP(S) `.js` resource on the same origin as `base`.
///
/// # Arguments
///
/// - `url`: resolved candidate.
/// - `base`: page the candidate was extracted from.
///
/// # Returns
///
/// `true` only for same-scheme, same-host paths ending in `.js`.
///
/// # Examples
///
/// ```text
/// if is_same_origin_script(&url, &base) { /* keep */ }
/// ```
fn is_same_origin_script(url: &Url, base: &Url) -> bool {
    url.scheme() == base.scheme()
        && url.host_str() == base.host_str()
        && url.path().ends_with(".js")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_fake_gateway_200() {
        let markers = vec!["接口不存在".to_string(), "code=404".to_string()];
        assert_eq!(value_score(200, "xxx接口不存在，code=404", &markers), 0);
        assert_eq!(value_score(403, "forbidden", &markers), 20);
    }

    #[test]
    fn negative_markers_are_case_insensitive_and_require_min_length() {
        let markers = vec!["CODE=404".to_string(), "a".to_string()];
        assert_eq!(value_score(200, "page with code=404 inside", &markers), 0);
        assert_eq!(value_score(200, "contains a single short letter", &markers), 50);
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
