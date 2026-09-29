//! Web directory enumeration and lightweight page parsing.
//!
//! In-flight HTTP requests are capped by `web.concurrency`, independent of
//! `probe.concurrency`. Dictionary paths, base URLs, JS URLs, and pending
//! replay all share that cap. `probe.per_target_delay_ms` still occupies a
//! worker after each dictionary or JS fetch.

mod fetch;
mod paths;

use std::{
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use futures::{StreamExt, stream};
use regex::Regex;
use reqwest::Client;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::{
    config::AppConfig, db::Database, models::BatchContext, monitor::fingerprint::enumeration_client,
};

use fetch::{WaveState, collect_enum_jobs, flush_deferred, run_wave, take_js_jobs};
use paths::fetch_candidate;

static INTERESTING_PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:src|href)\s*=\s*["']([^"']+)["']|["']((?:/[a-zA-Z0-9_./-]+|[a-zA-Z0-9_./-]+\.(?:js|html|json|action|do)))["']"#)
        .expect("static regex must compile")
});

/// Enumerates paths on identified Web services and records valuable URL assets.
///
/// # Arguments
///
/// - `db`: database handle for Web services, dictionary paths, and URL assets.
/// - `config`: reads `web.concurrency`, path caps, delay, and negative body markers.
/// - `batch`: current monitoring batch.
///
/// # Returns
///
/// `Ok(())` after pending replay and every scheduled URL fetch have finished.
///
/// # Errors
///
/// Returns an error if the HTTP client cannot be built, pending work cannot be
/// claimed or finished, Web services cannot be listed, or the dictionary cannot
/// be read. Per-URL write failures are logged only.
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
    let client = enumeration_client(config)?;
    let concurrency = config.web.concurrency();
    let started = Instant::now();
    let replayed = replay_pending_work(db, &client, config, batch, concurrency).await?;

    let services = db.list_web_services()?;
    let dict = db.list_dict_paths(config.web.max_paths_per_service)?;
    let jobs = collect_enum_jobs(db, &services, &dict);
    let candidate_count = jobs.len();
    info!(
        concurrency,
        service_count = services.len(),
        dict_path_count = dict.len(),
        candidate_count,
        replayed_pending = replayed,
        "web path scan started"
    );

    let state = WaveState::new(db.should_stop_batch(&batch.id)?);
    run_wave(db, &client, config, &batch.id, jobs, concurrency, &state).await;
    flush_deferred(db, &batch.id, &state)?;

    if !state.stopped() {
        let js_jobs = take_js_jobs(&state, config.web.max_js_paths_per_service);
        info!(
            js_candidate_count = js_jobs.len(),
            concurrency, "web path scan js urls queued"
        );
        run_wave(db, &client, config, &batch.id, js_jobs, concurrency, &state).await;
        flush_deferred(db, &batch.id, &state)?;
    }

    info!(
        completed = state.completed(),
        candidate_count,
        elapsed_ms = started.elapsed().as_millis(),
        "web path scan finished"
    );
    Ok(())
}

/// Replays unfinished web-enumeration URLs before starting new work.
///
/// Claimed rows are fetched under `concurrency`. Unclaimed rows stay pending
/// when the batch is asked to stop.
///
/// # Arguments
///
/// - `db`: database handle for the pending queue and URL assets.
/// - `client`: shared HTTP client.
/// - `config`: reads delay and negative markers.
/// - `batch`: current monitoring batch.
/// - `concurrency`: in-flight request cap from `web.concurrency`.
///
/// # Returns
///
/// Number of pending rows claimed during this call.
///
/// # Errors
///
/// Returns an error if the stop flag cannot be queried, pending items cannot
/// be taken, or a claimed item cannot be marked done.
///
/// # Examples
///
/// ```text
/// replay_pending_work(db, &client, config, batch, concurrency).await?;
/// ```
async fn replay_pending_work(
    db: &Database,
    client: &Client,
    config: &AppConfig,
    batch: &BatchContext,
    concurrency: usize,
) -> anyhow::Result<usize> {
    let mut replayed = 0usize;
    loop {
        if db.should_stop_batch(&batch.id)? {
            break;
        }
        let claimed = db.take_pending_work("web_enum", concurrency)?;
        if claimed.is_empty() {
            break;
        }
        let before = replayed;
        replayed += claimed.len();
        let failed = Arc::new(AtomicBool::new(false));
        stream::iter(claimed)
            .for_each_concurrent(concurrency, |work| {
                let db = db.clone();
                let client = client.clone();
                let failed = Arc::clone(&failed);
                async move {
                    match fetch_candidate(&client, &work.target, config).await {
                        Ok(Some(result)) => {
                            if result.score > 0
                                && let Err(error) = db.upsert_url(
                                    &work.system_id,
                                    &work.target,
                                    "discovered",
                                    Some(result.status),
                                    result.score,
                                )
                            {
                                warn!(
                                    url = %work.target,
                                    %error,
                                    "web enumeration pending url write failed"
                                );
                                if let Err(error) = db.retry_pending_work(&work.id) {
                                    warn!(id = %work.id, %error, "web enumeration pending retry failed");
                                    failed.store(true, Ordering::Relaxed);
                                }
                            } else if let Err(error) = db.finish_pending_work(&work.id) {
                                warn!(id = %work.id, %error, "web enumeration pending finish failed");
                                failed.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(None) => {
                            warn!(url = %work.target, "web enumeration pending fetch returned no response");
                            if let Err(error) = db.retry_pending_work(&work.id) {
                                warn!(id = %work.id, %error, "web enumeration pending retry failed");
                                failed.store(true, Ordering::Relaxed);
                            }
                        }
                        Err(error) => {
                            warn!(url = %work.target, %error, "web enumeration pending fetch failed");
                            if let Err(error) = db.retry_pending_work(&work.id) {
                                warn!(id = %work.id, %error, "web enumeration pending retry failed");
                                failed.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                    sleep(config.per_target_delay()).await;
                }
            })
            .await;
        if failed.load(Ordering::Relaxed) {
            anyhow::bail!("web enumeration failed to finish pending work");
        }
        if replayed / 1_000 > before / 1_000 {
            info!(
                replayed,
                concurrency, "web enumeration pending replay progress"
            );
        }
    }
    if replayed > 0 {
        info!(replayed, "web enumeration pending replay finished");
    }
    Ok(replayed)
}
