//! Lightweight vulnerability checks.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use futures::{StreamExt, stream};
use reqwest::Client;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::{
    config::AppConfig,
    db::Database,
    models::{BatchContext, UrlAsset},
    monitor::{
        fingerprint::http_client,
        vuln_sourcemap::{check_sourcemap, is_sourcemap_input_url},
    },
};

/// Runs lightweight POCs against URL assets; currently webpack source-map leak
/// detection.
///
/// Replays unfinished work first, then concurrently checks JavaScript /
/// `.js.map` URLs after applying the configured cap.
///
/// # Arguments
///
/// - `db`: persistence handle for assets, pending work, vulns, and alerts.
/// - `config`: runtime config for the POC switch, HTTP concurrency, and timeout.
/// - `batch`: current monitoring batch context.
///
/// # Returns
///
/// `Ok(())` when the POC is disabled, there are no URLs to check, or every URL
/// has been processed.
///
/// # Errors
///
/// Returns an error if the HTTP client cannot be built, pending work cannot be
/// replayed, or the URL list cannot be queried. Per-URL check failures are
/// logged only.
///
/// # Examples
///
/// ```no_run
/// # use watcher::{config::AppConfig, db::Database, models::BatchContext, monitor::vuln};
/// # async fn demo(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
/// vuln::run(db, config, batch).await?;
/// # Ok(())
/// # }
/// ```
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
    let concurrency = config.http_concurrency();
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

/// Replays unfinished vulnerability-scan URLs before starting new work.
///
/// # Arguments
///
/// - `db`: database handle for the pending queue and vuln results.
/// - `client`: shared HTTP client.
/// - `config`: runtime config for per-target delay.
/// - `batch`: current monitoring batch.
///
/// # Returns
///
/// Number of pending items replayed successfully. Returns early if the batch
/// is asked to stop or the queue is empty.
///
/// # Errors
///
/// Returns an error if the stop flag cannot be queried or pending items cannot
/// be taken / completed. Per-item POC failures are logged only.
///
/// # Examples
///
/// ```text
/// let replayed = replay_pending_work(db, &client, config, batch).await?;
/// ```
async fn replay_pending_work(
    db: &Database,
    client: &Client,
    config: &AppConfig,
    batch: &BatchContext,
) -> anyhow::Result<usize> {
    let mut replayed = 0usize;
    loop {
        if db.should_stop_batch(&batch.id)? {
            break;
        }
        let Some(work) = db.take_pending_work("vuln_scan", 1)?.pop() else {
            break;
        };
        if replayed == 0 {
            info!(
                batch = %batch.id,
                "task5 vuln scan replaying pending work"
            );
        }
        let fake = UrlAsset {
            id: work.id.clone(),
            system_id: work.system_id,
            system_name: String::new(),
            url: work.target,
            source: "pending".to_string(),
            status_code: None,
            value_score: 0,
            is_baseline: false,
        };
        if let Err(error) = check_sourcemap(db, client, config, &batch.id, &fake).await {
            warn!(url = %fake.url, %error, "task5 pending vuln scan failed");
        }
        db.finish_pending_work(&fake.id)?;
        replayed += 1;
        sleep(config.per_target_delay()).await;
    }
    Ok(replayed)
}

/// Computes the interval for task5 aggregated progress logs.
///
/// # Arguments
///
/// - `url_count`: number of URLs queued in this batch.
///
/// # Returns
///
/// Logs every item when there are at most 20; otherwise about 1% of the
/// total, and at least 20.
///
/// # Examples
///
/// ```text
/// let interval = vuln_scan_progress_interval(total_urls);
/// ```
fn vuln_scan_progress_interval(url_count: usize) -> usize {
    match url_count {
        0..=20 => url_count.max(1),
        _ => (url_count / 100).max(20),
    }
}

/// Returns whether task5 should log per-URL detail.
///
/// # Arguments
///
/// - `total_urls`: number of URLs queued in this batch.
///
/// # Returns
///
/// `true` when the total is at most 20.
///
/// # Examples
///
/// ```text
/// if should_log_vuln_url_detail(total_urls) { /* info */ }
/// ```
fn should_log_vuln_url_detail(total_urls: usize) -> bool {
    total_urls <= 20
}

/// Returns whether the completed count should emit an aggregated progress log.
///
/// # Arguments
///
/// - `completed`: number of processed URLs.
/// - `total`: queued total.
/// - `interval`: interval from [`vuln_scan_progress_interval`].
///
/// # Returns
///
/// `true` when everything is done, or `completed` is divisible by the
/// interval.
///
/// # Examples
///
/// ```text
/// if should_log_vuln_scan_progress(completed, total, interval) { /* info */ }
/// ```
fn should_log_vuln_scan_progress(completed: usize, total: usize, interval: usize) -> bool {
    completed == total || completed.is_multiple_of(interval.max(1))
}

/// Threshold above which a single URL is logged as a slow request.
///
/// # Arguments
///
/// - `config`: runtime config for HTTP timeout.
///
/// # Returns
///
/// The larger of `3 * http_timeout` and 30 seconds.
///
/// # Examples
///
/// ```text
/// if elapsed >= slow_vuln_url_threshold(config) { /* warn */ }
/// ```
fn slow_vuln_url_threshold(config: &AppConfig) -> Duration {
    (config.http_timeout() * 3).max(Duration::from_secs(30))
}
