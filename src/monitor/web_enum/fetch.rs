//! Bounded URL fetches for web enumeration.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use futures::{StreamExt, stream};
use reqwest::Client;
use tracing::{info, warn};
use url::Url;

use super::{
    paths::{self, CandidateResult, fetch_candidate},
    rate::{HostLimiter, url_origin},
};
use crate::{
    config::AppConfig,
    db::Database,
    models::PortAsset,
    monitor::progress::{
        SampledFailures, scan_progress_interval, should_log_scan_progress, warn_sampled_overflow,
    },
};

const STOP_CHECK_EVERY: usize = 64;

/// When a fetched body may contribute JS URLs.
#[derive(Clone, Copy)]
enum ExtractMode {
    /// Do not parse the body.
    No,
    /// Parse any successful fetch, including score 0.
    AnyBody,
    /// Parse only a non-negative HTTP 200.
    Scored200,
}

/// One URL fetch scheduled by web enumeration.
pub(super) struct EnumJob {
    system_id: String,
    pub(super) url: String,
    source: &'static str,
    /// Persist the status even when the value score is 0. Used for base URLs.
    keep_unscored: bool,
    extract: ExtractMode,
    apply_delay: bool,
    /// `0` means a stopped job is not written back to pending work.
    pending_priority: i64,
}

/// URL left unfetched because the batch was asked to stop.
pub(super) struct DeferredPending {
    pub(super) system_id: String,
    pub(super) url: String,
    pub(super) priority: i64,
}

impl EnumJob {
    /// Builds a JS-fetch job from a discovered script URL.
    ///
    /// # Arguments
    /// - `system_id`: owning business system.
    /// - `url`: absolute script URL.
    ///
    /// # Returns
    /// A delayed JS job that does not parse further bodies.
    ///
    /// # Examples
    /// ```text
    /// let job = EnumJob::js_discovered(system_id, url);
    /// ```
    pub(super) fn js_discovered(system_id: String, url: String) -> Self {
        EnumJob {
            system_id,
            url,
            source: "js_discovered",
            keep_unscored: false,
            extract: ExtractMode::No,
            apply_delay: true,
            pending_priority: 5,
        }
    }
}

/// Shared stop flag, deferred queue, and JS-path collector for one scan.
pub(super) struct WaveState {
    stop: Arc<AtomicBool>,
    pub(super) deferred: Arc<Mutex<Vec<DeferredPending>>>,
    pub(super) js_paths: Arc<Mutex<HashMap<String, BTreeSet<String>>>>,
    base_bodies: Arc<Mutex<HashMap<String, String>>>,
    completed: Arc<AtomicUsize>,
    pub(super) fetch_failures: Arc<SampledFailures>,
    pub(super) write_failures: Arc<SampledFailures>,
}

impl WaveState {
    /// Creates wave state, optionally already stopped.
    ///
    /// # Arguments
    ///
    /// - `stopped`: initial stop flag from the batch row.
    ///
    /// # Returns
    ///
    /// Empty collectors and a zero completion counter.
    ///
    /// # Examples
    ///
    /// ```text
    /// let state = WaveState::new(false);
    /// ```
    pub(super) fn new(stopped: bool) -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(stopped)),
            deferred: Arc::new(Mutex::new(Vec::new())),
            js_paths: Arc::new(Mutex::new(HashMap::new())),
            base_bodies: Arc::new(Mutex::new(HashMap::new())),
            completed: Arc::new(AtomicUsize::new(0)),
            fetch_failures: Arc::new(SampledFailures::new()),
            write_failures: Arc::new(SampledFailures::new()),
        }
    }

    /// Returns whether more fetches should be skipped.
    ///
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// `true` after a stop request has been observed.
    ///
    /// # Examples
    ///
    /// ```text
    /// if state.stopped() { /* skip js wave */ }
    /// ```
    pub(super) fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Returns how many URLs were actually fetched.
    ///
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// Completion count across waves. Deferred URLs are not included.
    ///
    /// # Examples
    ///
    /// ```text
    /// let n = state.completed();
    /// ```
    pub(super) fn completed(&self) -> usize {
        self.completed.load(Ordering::Relaxed)
    }
}

/// Builds base and dictionary fetch jobs. Base URLs are recorded before fetch.
///
/// # Arguments
///
/// - `db`: database handle for domains and the initial base-URL write.
/// - `services`: identified Web port assets.
/// - `dict`: path dictionary for this batch.
///
/// # Returns
///
/// Fetch jobs. A service that cannot be expanded is logged and skipped.
///
/// # Examples
///
/// ```text
/// let jobs = collect_enum_jobs(db, &services, &dict);
/// ```
pub(super) fn collect_enum_jobs(
    db: &Database,
    services: &[PortAsset],
    dict: &[String],
) -> Vec<EnumJob> {
    let mut jobs = Vec::new();
    let skipped_services = SampledFailures::new();
    let invalid_paths = SampledFailures::new();
    for service in services {
        match service_jobs(db, service, dict, &invalid_paths) {
            Ok(mut service_jobs) => jobs.append(&mut service_jobs),
            Err(error) => skipped_services
                .note_with(|| warn!(service = ?service, %error, "web enumeration skipped service")),
        }
    }
    warn_sampled_overflow(skipped_services.count(), "web enumeration skipped service");
    warn_sampled_overflow(
        invalid_paths.count(),
        "web enumeration skipped invalid dictionary path",
    );
    jobs
}

/// Expands one Web service into base and dictionary jobs.
///
/// # Arguments
///
/// - `db`: database handle for domains and the base-URL write.
/// - `service`: identified Web port asset.
/// - `dict`: path dictionary for this batch.
///
/// # Returns
///
/// Jobs for every base URL and dictionary path.
///
/// # Errors
///
/// Returns an error if a base URL cannot be built or the initial base-URL row
/// cannot be written.
///
/// # Examples
///
/// ```text
/// let jobs = service_jobs(db, service, dict)?;
/// ```
fn service_jobs(
    db: &Database,
    service: &PortAsset,
    dict: &[String],
    invalid_paths: &SampledFailures,
) -> anyhow::Result<Vec<EnumJob>> {
    let bases = paths::service_base_urls(db, service)?;
    let mut jobs = Vec::with_capacity(bases.len().saturating_mul(dict.len().saturating_add(1)));
    for base in bases {
        db.upsert_url(&service.system_id, base.as_str(), "discovered", None, 20)?;
        let mut seen = BTreeSet::new();
        let base_url = base.to_string();
        seen.insert(base_url.clone());
        jobs.push(base_job(&service.system_id, base_url));
        for path in dict {
            let normalized = path.trim().trim_start_matches('/');
            if normalized.is_empty() {
                continue;
            }
            let Ok(candidate) = base.join(normalized) else {
                invalid_paths.note_with(
                    || warn!(base = %base, path, "web enumeration skipped invalid dictionary path"),
                );
                continue;
            };
            let url = candidate.to_string();
            if !seen.insert(url.clone()) {
                continue;
            }
            jobs.push(dict_job(&service.system_id, url));
        }
    }
    Ok(jobs)
}

/// Builds the uncapped base-URL job.
///
/// # Arguments
///
/// - `system_id`: owning business system.
/// - `url`: absolute base URL.
///
/// # Returns
///
/// A job that records every status and extracts JS paths.
///
/// # Examples
///
/// ```text
/// let job = base_job(system_id, url);
/// ```
fn base_job(system_id: &str, url: String) -> EnumJob {
    EnumJob {
        system_id: system_id.to_string(),
        url,
        source: "discovered",
        keep_unscored: true,
        extract: ExtractMode::AnyBody,
        apply_delay: false,
        pending_priority: 0,
    }
}

/// Builds one dictionary-path job.
///
/// # Arguments
///
/// - `system_id`: owning business system.
/// - `url`: absolute candidate URL.
///
/// # Returns
///
/// A delayed job that is deferred on stop and extracts JS only from a useful 200.
///
/// # Examples
///
/// ```text
/// let job = dict_job(system_id, url);
/// ```
fn dict_job(system_id: &str, url: String) -> EnumJob {
    EnumJob {
        system_id: system_id.to_string(),
        url,
        source: "discovered",
        keep_unscored: false,
        extract: ExtractMode::Scored200,
        apply_delay: true,
        pending_priority: 10,
    }
}

/// Fetches `jobs` with at most `concurrency` requests in flight.
///
/// # Arguments
///
/// - `db`: database handle for URL writes and the stop flag.
/// - `client`: shared HTTP client.
/// - `config`: reads delay and negative markers.
/// - `batch_id`: current batch id.
/// - `jobs`: URLs to fetch.
/// - `concurrency`: in-flight request cap. Must be at least 1.
/// - `state`: stop flag, deferred queue, and JS collector.
///
/// # Examples
///
/// ```text
/// run_wave(db, client, config, batch_id, jobs, concurrency, &state).await;
/// ```
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_wave(
    db: &Database,
    client: &Client,
    config: &AppConfig,
    batch_id: &str,
    jobs: Vec<EnumJob>,
    concurrency: usize,
    state: &WaveState,
    limiter: Arc<HostLimiter>,
) {
    let total = jobs.len();
    if total == 0 {
        return;
    }
    let progress_interval = scan_progress_interval(total);
    let wave_completed = Arc::new(AtomicUsize::new(0));
    stream::iter(jobs)
        .for_each_concurrent(concurrency, |job| {
            let db = db.clone();
            let client = client.clone();
            let state_stop = Arc::clone(&state.stop);
            let deferred = Arc::clone(&state.deferred);
            let js_paths = Arc::clone(&state.js_paths);
            let base_bodies = Arc::clone(&state.base_bodies);
            let completed = Arc::clone(&state.completed);
            let fetch_failures = Arc::clone(&state.fetch_failures);
            let write_failures = Arc::clone(&state.write_failures);
            let wave_completed = Arc::clone(&wave_completed);
            let limiter = Arc::clone(&limiter);
            let batch_id = batch_id.to_string();
            async move {
                if state_stop.load(Ordering::Relaxed) {
                    defer_job(&job, &deferred);
                    return;
                }
                if job.apply_delay {
                    limiter.wait(&job.url, config.per_target_delay()).await;
                }
                match fetch_candidate(&client, &job.url, config).await {
                    Ok(Some(mut result)) => {
                        match job.extract {
                            ExtractMode::AnyBody => {
                                if let Some(origin) = url_origin(&job.url) {
                                    base_bodies
                                        .lock()
                                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                                        .insert(origin, result.body.clone());
                                }
                            }
                            ExtractMode::Scored200 => {
                                let same_page = url_origin(&job.url).is_some_and(|origin| {
                                    base_bodies
                                        .lock()
                                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                                        .get(&origin)
                                        .is_some_and(|base| base == &result.body)
                                });
                                if same_page {
                                    result.score = 0;
                                }
                            }
                            ExtractMode::No => {}
                        }
                        record_result(&db, &job, &result, &write_failures);
                        if should_extract(job.extract, &result) {
                            collect_js_paths(
                                &js_paths,
                                &job,
                                &result.body,
                                config.web.max_js_paths_per_service,
                            );
                        }
                    }
                    Ok(None) => {}
                    Err(error) => fetch_failures.note_with(
                        || warn!(url = %job.url, %error, "web enumeration fetch failed"),
                    ),
                }
                let done = wave_completed.fetch_add(1, Ordering::Relaxed) + 1;
                completed.fetch_add(1, Ordering::Relaxed);
                if done.is_multiple_of(STOP_CHECK_EVERY)
                    && matches!(db.should_stop_batch(&batch_id), Ok(true))
                {
                    state_stop.store(true, Ordering::Relaxed);
                }
                if should_log_scan_progress(done, total, progress_interval) {
                    info!(
                        completed = done,
                        total,
                        progress = %format!("{done}/{total}"),
                        "web path scan progress"
                    );
                }
            }
        })
        .await;
}

/// Persists a fetch when the job keeps unscored results or the score is positive.
///
/// # Arguments
///
/// - `db`: database handle for URL assets.
/// - `job`: source job.
/// - `result`: status, body, and score.
/// - `write_failures`: sampled write-failure counter.
///
/// # Examples
///
/// ```text
/// record_result(db, &job, &result, &write_failures);
/// ```
fn record_result(
    db: &Database,
    job: &EnumJob,
    result: &CandidateResult,
    write_failures: &SampledFailures,
) {
    if !job.keep_unscored && result.score <= 0 {
        return;
    }
    if let Err(error) = db.upsert_url(
        &job.system_id,
        &job.url,
        job.source,
        Some(result.status),
        result.score,
    ) {
        write_failures
            .note_with(|| warn!(url = %job.url, %error, "web enumeration url write failed"));
    }
}

/// Returns whether this fetch should contribute JS URLs.
///
/// # Arguments
///
/// - `mode`: extraction policy for the job.
/// - `result`: HTTP status, body prefix, and value score.
///
/// # Returns
///
/// `true` when the body should be parsed.
///
/// # Examples
///
/// ```text
/// let extract = should_extract(ExtractMode::Scored200, &result);
/// ```
fn should_extract(mode: ExtractMode, result: &CandidateResult) -> bool {
    match mode {
        ExtractMode::No => false,
        ExtractMode::AnyBody => true,
        ExtractMode::Scored200 => result.score > 0 && result.status == 200,
    }
}

/// Inserts absolute HTTP(S) references found in one response.
///
/// # Arguments
///
/// - `js_paths`: per-system URL set shared by the fetch wave.
/// - `job`: source job. Its URL resolves relative references.
/// - `body`: response-body prefix.
///
/// # Examples
///
/// ```text
/// collect_js_paths(&js_paths, &job, &result.body);
/// ```
fn collect_js_paths(
    js_paths: &Mutex<HashMap<String, BTreeSet<String>>>,
    job: &EnumJob,
    body: &str,
    limit: usize,
) {
    let Ok(base) = Url::parse(&job.url) else {
        return;
    };
    let found = paths::extract_interesting_paths(body, &base);
    if found.is_empty() || limit == 0 {
        return;
    }
    let mut paths = js_paths
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let set = paths.entry(job.system_id.clone()).or_default();
    for url in found {
        if set.len() >= limit {
            break;
        }
        set.insert(url);
    }
}

/// Queues a stopped dictionary or JS job for the next batch.
///
/// # Arguments
///
/// - `job`: job that was not fetched.
/// - `deferred`: collector flushed after the wave.
///
/// # Examples
///
/// ```text
/// defer_job(&job, &deferred);
/// ```
fn defer_job(job: &EnumJob, deferred: &Mutex<Vec<DeferredPending>>) {
    if job.pending_priority <= 0 {
        return;
    }
    deferred
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(DeferredPending {
            system_id: job.system_id.clone(),
            url: job.url.clone(),
            priority: job.pending_priority,
        });
}

/// Writes deferred URLs and clears the collector.
///
/// # Arguments
///
/// - `db`: database handle for pending work.
/// - `batch_id`: current batch id.
/// - `state`: wave state holding the deferred queue.
///
/// # Returns
///
/// `Ok(())` when the collector is empty or the rows are written.
///
/// # Errors
///
/// Returns an error if the pending-work transaction fails.
///
/// # Examples
///
/// ```text
/// flush_deferred(db, batch_id, &state)?;
/// ```
pub(super) fn flush_deferred(
    db: &Database,
    batch_id: &str,
    state: &WaveState,
) -> anyhow::Result<()> {
    let items = std::mem::take(
        &mut *state
            .deferred
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
    if items.is_empty() {
        return Ok(());
    }
    let refs: Vec<(&str, &str, i64)> = items
        .iter()
        .map(|item| (item.system_id.as_str(), item.url.as_str(), item.priority))
        .collect();
    db.add_pending_work_batch(batch_id, "web_enum", &refs)?;
    info!(
        deferred = refs.len(),
        "web enumeration deferred unfinished urls"
    );
    Ok(())
}
