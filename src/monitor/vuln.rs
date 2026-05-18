//! Lightweight vulnerability checks.

use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
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
    models::{BatchContext, UrlAsset},
    monitor::fingerprint::http_client,
};

/// Runs lightweight POCs against URL assets.
pub async fn run(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
    let poc = &config.pocs.webpack_sourcemap_disclosure;
    if !poc.enabled {
        info!(
            batch = %batch.id,
            poc = "webpack_sourcemap_disclosure",
            "vulnerability poc disabled"
        );
        return Ok(());
    }

    let client = http_client(config)?;
    let started = Instant::now();
    let replayed_pending = replay_pending_work(db, &client, config, batch).await?;

    let all_urls = db.list_urls()?;
    let discovered_urls = all_urls.len();
    let mut urls: Vec<_> = all_urls
        .into_iter()
        .filter(|asset| is_sourcemap_input_url(&asset.url))
        .collect();
    let eligible_urls = urls.len();
    let max_urls = poc.max_urls_per_batch();
    if urls.len() > max_urls {
        urls.truncate(max_urls);
        warn!(
            batch = %batch.id,
            discovered_urls,
            max_urls,
            "task5 vuln scan url list truncated by config"
        );
    }
    let total_urls = urls.len();
    let concurrency = config.probe.concurrency.clamp(1, 8);
    let db_clone = db.clone();
    let completed_urls = Arc::new(AtomicUsize::new(0));
    let checked_maps = Arc::new(AtomicUsize::new(0));
    let findings = Arc::new(AtomicUsize::new(0));
    let progress_interval = vuln_scan_progress_interval(total_urls);

    info!(
        batch = %batch.id,
        poc = "webpack_sourcemap_disclosure",
        replayed_pending,
        discovered_urls,
        eligible_urls,
        queued_urls = total_urls,
        concurrency,
        max_js_files_per_url = poc.max_js_files_per_url(),
        max_map_candidates_per_url = poc.max_map_candidates_per_url(),
        "task5 vuln scan queued urls"
    );
    if total_urls == 0 {
        info!(
            batch = %batch.id,
            elapsed_ms = started.elapsed().as_millis(),
            "task5 vuln scan skipped because no js or sourcemap urls were queued"
        );
        return Ok(());
    }

    let scan_completed_urls = Arc::clone(&completed_urls);
    let scan_checked_maps = Arc::clone(&checked_maps);
    let scan_findings = Arc::clone(&findings);
    stream::iter(urls)
        .for_each_concurrent(concurrency, move |asset| {
            let db = db_clone.clone();
            let client = client.clone();
            let batch_id = batch.id.clone();
            let completed_urls = Arc::clone(&scan_completed_urls);
            let checked_maps = Arc::clone(&scan_checked_maps);
            let findings = Arc::clone(&scan_findings);
            async move {
                if matches!(db.should_stop_batch(&batch_id), Ok(true)) {
                    let _ = db.add_pending_work(
                        &batch_id,
                        &asset.system_id,
                        "vuln_scan",
                        &asset.url,
                        5,
                    );
                    let completed = completed_urls.fetch_add(1, Ordering::Relaxed) + 1;
                    info!(
                        batch = %batch_id,
                        progress = %format!("{completed}/{total_urls}"),
                        url = %asset.url,
                        "task5 vuln scan url deferred because stop was requested"
                    );
                    return;
                }

                let url_started = Instant::now();
                if should_log_vuln_url_detail(total_urls) {
                    info!(
                        batch = %batch_id,
                        url = %asset.url,
                        "task5 vuln scan url started"
                    );
                }
                match check_sourcemap(&db, &client, config, &batch_id, &asset).await {
                    Ok(stats) => {
                        checked_maps.fetch_add(stats.map_candidates_checked, Ordering::Relaxed);
                        findings.fetch_add(stats.findings, Ordering::Relaxed);
                        let completed = completed_urls.fetch_add(1, Ordering::Relaxed) + 1;
                        if should_log_vuln_url_detail(total_urls)
                            || should_log_vuln_scan_progress(
                                completed,
                                total_urls,
                                progress_interval,
                            )
                        {
                            info!(
                                batch = %batch_id,
                                progress = %format!("{completed}/{total_urls}"),
                                url = %asset.url,
                                script_urls = stats.script_urls_seen,
                                script_urls_checked = stats.script_urls_checked,
                                map_candidates_checked = stats.map_candidates_checked,
                                findings = stats.findings,
                                elapsed_ms = url_started.elapsed().as_millis(),
                                "task5 vuln scan url finished"
                            );
                        } else if url_started.elapsed() >= slow_vuln_url_threshold(config) {
                            warn!(
                                batch = %batch_id,
                                progress = %format!("{completed}/{total_urls}"),
                                url = %asset.url,
                                elapsed_ms = url_started.elapsed().as_millis(),
                                "task5 vuln scan url was slow"
                            );
                        }
                    }
                    Err(error) => {
                        let completed = completed_urls.fetch_add(1, Ordering::Relaxed) + 1;
                        warn!(
                            batch = %batch_id,
                            progress = %format!("{completed}/{total_urls}"),
                            url = %asset.url,
                            elapsed_ms = url_started.elapsed().as_millis(),
                            %error,
                            "task5 vuln scan url failed"
                        );
                    }
                }
            }
        })
        .await;

    info!(
        batch = %batch.id,
        completed_urls = completed_urls.load(Ordering::Relaxed),
        queued_urls = total_urls,
        checked_maps = checked_maps.load(Ordering::Relaxed),
        findings = findings.load(Ordering::Relaxed),
        elapsed_ms = started.elapsed().as_millis(),
        "task5 vuln scan all urls processed"
    );

    Ok(())
}

/// Replays old unfinished vulnerability scan URLs before new work.
async fn replay_pending_work(
    db: &Database,
    client: &Client,
    config: &AppConfig,
    batch: &BatchContext,
) -> anyhow::Result<usize> {
    let pending = db.take_pending_work("vuln_scan", 100)?;
    if !pending.is_empty() {
        info!(
            batch = %batch.id,
            pending_count = pending.len(),
            "task5 vuln scan replaying pending work"
        );
    }
    let mut replayed = 0usize;
    for (id, target) in pending {
        if db.should_stop_batch(&batch.id)? {
            break;
        }
        let fake = UrlAsset {
            id: id.clone(),
            system_id: String::new(),
            system_name: String::new(),
            url: target,
            source: "pending".to_string(),
            status_code: None,
            value_score: 0,
            is_baseline: false,
        };
        let _ = collect_sourcemap_candidates(client, config, &fake.url).await;
        db.finish_pending_work(&id)?;
        replayed += 1;
        sleep(config.per_target_delay()).await;
    }
    Ok(replayed)
}

/// Checks whether webpack JavaScript source maps are exposed.
async fn check_sourcemap(
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
        let body = response.text().await.unwrap_or_default();
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

/// Collects source map candidate URLs by fetching a page or JS asset.
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
            Ok(response) => response.text().await.unwrap_or_default(),
            Err(_) => continue,
        };
        if let Some(marker) = source_mapping_url(&js_body)
            && let Ok(js_base) = Url::parse(&js_url)
            && let Ok(map_url) = js_base.join(&marker)
        {
            candidates.insert(map_url.to_string());
        }
        if js_url.ends_with(".js") {
            candidates.insert(format!("{js_url}.map"));
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

/// Returns true when a URL is useful input for source map checking.
fn is_sourcemap_input_url(url: &str) -> bool {
    Url::parse(url)
        .map(|url| is_javascript_url(&url) || is_sourcemap_url(&url))
        .unwrap_or(false)
}

/// Returns true for JavaScript asset URLs, including URLs with query strings.
fn is_javascript_url(url: &Url) -> bool {
    url.path().to_ascii_lowercase().ends_with(".js")
}

/// Returns true for source map asset URLs, including URLs with query strings.
fn is_sourcemap_url(url: &Url) -> bool {
    url.path().to_ascii_lowercase().ends_with(".js.map")
}

/// Source map candidates gathered from one URL.
#[derive(Debug, Default)]
struct SourcemapCandidates {
    /// Candidate source map URLs.
    candidates: BTreeSet<String>,
    /// Script URLs extracted before per-URL limiting.
    script_urls_seen: usize,
    /// Script URLs fetched after per-URL limiting.
    script_urls_checked: usize,
}

/// Per-URL source map POC counters.
#[derive(Debug, Default)]
struct SourcemapScanStats {
    /// Script URLs extracted before per-URL limiting.
    script_urls_seen: usize,
    /// Script URLs fetched after per-URL limiting.
    script_urls_checked: usize,
    /// Source map candidates fetched and inspected.
    map_candidates_checked: usize,
    /// Source map findings written.
    findings: usize,
}

/// Returns how often task5 aggregate progress should be logged.
fn vuln_scan_progress_interval(url_count: usize) -> usize {
    match url_count {
        0..=20 => url_count.max(1),
        _ => (url_count / 100).max(20),
    }
}

/// Returns true when task5 should log per-URL detail.
fn should_log_vuln_url_detail(total_urls: usize) -> bool {
    total_urls <= 20
}

/// Returns true when a completed-URL count should emit aggregate progress.
fn should_log_vuln_scan_progress(completed: usize, total: usize, interval: usize) -> bool {
    completed == total || completed.is_multiple_of(interval.max(1))
}

/// Returns the elapsed threshold for warning about one slow URL.
fn slow_vuln_url_threshold(config: &AppConfig) -> Duration {
    (config.http_timeout() * 3).max(Duration::from_secs(30))
}

/// Finds a `sourceMappingURL` marker in JavaScript text.
fn source_mapping_url(body: &str) -> Option<String> {
    let regex =
        Regex::new(r#"(?m)//[#@]\s*sourceMappingURL=([^\s]+)"#).expect("static regex must compile");
    regex
        .captures(body)
        .and_then(|capture| capture.get(1))
        .map(|m| m.as_str().trim().to_string())
}

/// Returns true when a body has the common JSON shape of a source map.
fn looks_like_sourcemap(body: &str) -> bool {
    body.contains("\"version\"")
        && body.contains("\"sources\"")
        && (body.contains("\"mappings\"") || body.contains("\"sourcesContent\""))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
