//! Web directory enumeration and lightweight page parsing.
//!
//! In-flight HTTP requests are capped by `web.concurrency`, independent of
//! `probe.concurrency`. Dictionary paths, base URLs, JS URLs, and pending
//! replay all share that cap. `probe.per_target_delay_ms` still occupies a
//! worker after each dictionary or JS fetch.

mod fetch;
mod js;
mod paths;
mod rate;

use std::{
    collections::HashSet,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use futures::{StreamExt, stream};
use regex::Regex;
use reqwest::Client;
use tracing::{info, warn};

use crate::{
    config::AppConfig,
    db::Database,
    models::BatchContext,
    monitor::fingerprint::enumeration_client,
    monitor::progress::{SampledFailures, warn_sampled_overflow},
};

use fetch::{WaveState, collect_enum_jobs, flush_deferred, run_wave};
use js::{flush_js_paths_on_stop, take_js_jobs};
use paths::fetch_candidate;
use rate::HostLimiter;

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
    let limiter = Arc::new(HostLimiter::new());
    let (replayed, replayed_urls) = replay_pending_work(
        db,
        &client,
        config,
        batch,
        concurrency,
        Arc::clone(&limiter),
    )
    .await?;

    let services = db.list_web_services()?;
    let dict = db.list_dict_paths(config.web.max_paths_per_service)?;
    let mut jobs = collect_enum_jobs(db, &services, &dict);
    jobs.retain(|job| !replayed_urls.contains(&job.url));
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
    run_wave(
        db,
        &client,
        config,
        &batch.id,
        jobs,
        concurrency,
        &state,
        Arc::clone(&limiter),
    )
    .await;
    if state.stopped() {
        flush_js_paths_on_stop(&state);
    }
    flush_deferred(db, &batch.id, &state)?;

    if !state.stopped() {
        let js_jobs = take_js_jobs(&state, config.web.max_js_paths_per_service);
        info!(
            js_candidate_count = js_jobs.len(),
            concurrency, "web path scan js urls queued"
        );
        run_wave(
            db,
            &client,
            config,
            &batch.id,
            js_jobs,
            concurrency,
            &state,
            limiter,
        )
        .await;
        flush_deferred(db, &batch.id, &state)?;
    }

    warn_sampled_overflow(state.fetch_failures.count(), "web enumeration fetch failed");
    warn_sampled_overflow(
        state.write_failures.count(),
        "web enumeration url write failed",
    );
    info!(
        completed = state.completed(),
        candidate_count,
        fetch_failures = state.fetch_failures.count(),
        write_failures = state.write_failures.count(),
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
/// `(claimed count, targets that received a definitive response)`.
///
/// # Errors
///
/// Returns an error if the stop flag cannot be queried, pending items cannot
/// be taken, or a claimed item cannot be marked done.
///
/// # Examples
///
/// ```text
/// let (count, finished) = replay_pending_work(db, &client, config, batch, concurrency, limiter).await?;
/// ```
async fn replay_pending_work(
    db: &Database,
    client: &Client,
    config: &AppConfig,
    batch: &BatchContext,
    concurrency: usize,
    limiter: Arc<HostLimiter>,
) -> anyhow::Result<(usize, HashSet<String>)> {
    let mut replayed = 0usize;
    let finished: Arc<std::sync::Mutex<HashSet<String>>> =
        Arc::new(std::sync::Mutex::new(HashSet::new()));
    let fetch_failures = Arc::new(SampledFailures::new());
    let write_failures = Arc::new(SampledFailures::new());
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
                let limiter = Arc::clone(&limiter);
                let finished = Arc::clone(&finished);
                let fetch_failures = Arc::clone(&fetch_failures);
                let write_failures = Arc::clone(&write_failures);
                async move {
                    limiter.wait(&work.target, config.per_target_delay()).await;
                    match fetch_candidate(&client, &work.target, config).await {
                        Ok(Some(result)) => {
                            finished
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .insert(work.target.clone());
                            if result.score > 0
                                && let Err(error) = db.upsert_url(
                                    &work.system_id,
                                    &work.target,
                                    "discovered",
                                    Some(result.status),
                                    result.score,
                                )
                            {
                                write_failures.note_with(|| {
                                    warn!(
                                        url = %work.target,
                                        %error,
                                        "web enumeration pending url write failed"
                                    )
                                });
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
                            fetch_failures.note_with(|| {
                                warn!(url = %work.target, "web enumeration pending fetch returned no response")
                            });
                            if let Err(error) = db.retry_pending_work(&work.id) {
                                warn!(id = %work.id, %error, "web enumeration pending retry failed");
                                failed.store(true, Ordering::Relaxed);
                            }
                        }
                        Err(error) => {
                            fetch_failures.note_with(|| {
                                warn!(url = %work.target, %error, "web enumeration pending fetch failed")
                            });
                            if let Err(error) = db.retry_pending_work(&work.id) {
                                warn!(id = %work.id, %error, "web enumeration pending retry failed");
                                failed.store(true, Ordering::Relaxed);
                            }
                        }
                    }
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
    warn_sampled_overflow(
        fetch_failures.count(),
        "web enumeration pending fetch failed",
    );
    warn_sampled_overflow(
        write_failures.count(),
        "web enumeration pending url write failed",
    );
    if replayed > 0 {
        info!(
            replayed,
            fetch_failures = fetch_failures.count(),
            write_failures = write_failures.count(),
            "web enumeration pending replay finished"
        );
    }
    let finished = finished
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    Ok((replayed, finished))
}
