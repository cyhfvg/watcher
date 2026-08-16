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

/// Enumerates paths on identified Web services and records valuable URL assets.
///
/// # Arguments
///
/// - `db`: database handle for Web services, dictionary paths, and URL assets.
/// - `config`: reads HTTP concurrency, path caps, and negative body markers.
/// - `batch`: current monitoring batch.
///
/// # Returns
///
/// `Ok(())` after every service has been processed.
///
/// # Errors
///
/// Returns an error if the HTTP client cannot be built, pending work cannot be
/// replayed, Web services cannot be listed, or the dictionary cannot be read.
/// Per-service failures are logged only.
///
/// # Examples
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

/// Replays unfinished Web-enumeration URLs before starting new work.
///
/// # Arguments
///
/// - `db`: database handle for the pending queue and URL assets.
/// - `client`: shared HTTP client.
/// - `config`: reads per-target delay and negative markers.
/// - `batch`: current monitoring batch.
///
/// # Returns
///
/// `Ok(())` when the queue is empty or the batch is asked to stop.
///
/// # Errors
///
/// Returns an error if the stop flag cannot be queried, pending items cannot
/// be taken / completed, or a URL cannot be written.
///
/// # Examples
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

/// Enumerates a single Web service with dictionary paths and JS-discovered
/// paths.
///
/// # Arguments
///
/// - `db`: database handle for URL assets and the stop flag.
/// - `client`: shared HTTP client.
/// - `config`: reads delay, JS path cap, and negative markers.
/// - `batch_id`: current batch id.
/// - `service`: identified Web port asset.
/// - `dict`: path dictionary used for this batch.
///
/// # Returns
///
/// `Ok(())` when enumeration finishes or exits early due to a stop request.
///
/// # Errors
///
/// Returns an error if a base URL cannot be built, a URL / pending item cannot
/// be written, or a candidate fetch fails.
///
/// # Examples
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
/// The current implementation treats HTTP failures as `None` and usually does
/// not return an error.
///
/// # Examples
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
