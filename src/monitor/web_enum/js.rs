//! Turns discovered JS URLs into fetch jobs or pending work.

use super::fetch::{DeferredPending, EnumJob, WaveState};

/// Turns discovered references into a capped JS fetch wave.
///
/// # Arguments
///
/// - `state`: wave state holding the collected URLs. The collector is cleared.
/// - `limit`: `web.max_js_paths_per_service`.
///
/// # Returns
///
/// JS jobs at most `limit` per system. Overflow is queued as pending work.
///
/// # Examples
///
/// ```text
/// let jobs = take_js_jobs(&state, limit);
/// ```
pub(super) fn take_js_jobs(state: &WaveState, limit: usize) -> Vec<EnumJob> {
    let paths = std::mem::take(
        &mut *state
            .js_paths
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
    let mut jobs = Vec::new();
    let mut overflow = Vec::new();
    for (system_id, urls) in paths {
        for (index, url) in urls.into_iter().enumerate() {
            if index < limit {
                jobs.push(EnumJob::js_discovered(system_id.clone(), url));
            } else {
                overflow.push(DeferredPending {
                    system_id: system_id.clone(),
                    url,
                    priority: 5,
                });
            }
        }
    }
    if !overflow.is_empty() {
        state
            .deferred
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend(overflow);
    }
    jobs
}

/// Drains collected JS URLs into the deferred queue so a stopped wave still
/// replays them next batch.
///
/// # Arguments
///
/// - `state`: wave state holding the JS collector.
///
/// # Examples
///
/// ```text
/// flush_js_paths_on_stop(&state);
/// ```
pub(super) fn flush_js_paths_on_stop(state: &WaveState) {
    let paths = std::mem::take(
        &mut *state
            .js_paths
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
    if paths.is_empty() {
        return;
    }
    let deferred: Vec<DeferredPending> = paths
        .into_iter()
        .flat_map(|(system_id, urls)| {
            urls.into_iter().map(move |url| DeferredPending {
                system_id: system_id.clone(),
                url,
                priority: 5,
            })
        })
        .collect();
    state
        .deferred
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .extend(deferred);
}
