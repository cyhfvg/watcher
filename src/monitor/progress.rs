//! Shared aggregate scan progress helpers.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Computes the interval for aggregated scan-progress logs.
///
/// # Arguments
///
/// - `total`: total number of items to process.
///
/// # Returns
///
/// Logs every item when `total` is at most 100; otherwise about 1% of the
/// total, and at least 100.
///
/// # Examples
///
/// ```text
/// let interval = scan_progress_interval(ip_count);
/// ```
pub(crate) fn scan_progress_interval(total: usize) -> usize {
    match total {
        0..=100 => total.max(1),
        _ => (total / 100).max(100),
    }
}

/// Returns whether the completed count should emit an aggregated progress log.
///
/// # Arguments
///
/// - `completed`: number of processed items.
/// - `total`: total item count.
/// - `interval`: interval from [`scan_progress_interval`].
///
/// # Returns
///
/// `true` when everything is done, or `completed` is divisible by the
/// interval.
///
/// # Examples
///
/// ```text
/// if should_log_scan_progress(completed, total, interval) { /* info */ }
/// ```
pub(crate) fn should_log_scan_progress(completed: usize, total: usize, interval: usize) -> bool {
    completed == total || completed.is_multiple_of(interval.max(1))
}

/// Counts repeated failures and logs only the first sample.
#[derive(Default)]
pub(crate) struct SampledFailures {
    count: AtomicUsize,
}

impl SampledFailures {
    /// Creates a zeroed counter.
    ///
    /// # Arguments
    /// none
    ///
    /// # Returns
    /// Empty counter.
    ///
    /// # Examples
    /// ```text
    /// let failures = SampledFailures::new();
    /// ```
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Records one failure.
    ///
    /// # Arguments
    /// none
    ///
    /// # Returns
    /// `true` for the first failure so the caller can log a sample.
    ///
    /// # Examples
    /// ```text
    /// if failures.note() { warn!(%error, "fetch failed"); }
    /// ```
    pub(crate) fn note(&self) -> bool {
        self.count.fetch_add(1, Ordering::Relaxed) == 0
    }

    /// Records one failure and logs only the first sample.
    ///
    /// # Arguments
    /// - `log`: Closure that emits the sample warning.
    ///
    /// # Examples
    /// ```text
    /// failures.note_with(|| warn!(url = %url, %error, "fetch failed"));
    /// ```
    pub(crate) fn note_with(&self, log: impl FnOnce()) {
        if self.note() {
            log();
        }
    }

    /// Returns how many failures were recorded.
    ///
    /// # Arguments
    /// none
    ///
    /// # Returns
    /// Failure count.
    ///
    /// # Examples
    /// ```text
    /// let n = failures.count();
    /// ```
    pub(crate) fn count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
}

/// Logs a count when more than one sampled failure occurred.
///
/// # Arguments
/// - `count`: Total failures including the first sample.
/// - `message`: Shared warning text.
///
/// # Examples
/// ```text
/// warn_sampled_overflow(failures.count(), "web enumeration fetch failed");
/// ```
pub(crate) fn warn_sampled_overflow(count: usize, message: &'static str) {
    if count > 1 {
        tracing::warn!(count, "{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_interval_keeps_large_scans_coarse() {
        assert_eq!(scan_progress_interval(0), 1);
        assert_eq!(scan_progress_interval(2), 2);
        assert_eq!(scan_progress_interval(10_000), 100);
        assert_eq!(scan_progress_interval(100_000), 1_000);
    }

    #[test]
    fn progress_logs_on_interval_and_completion() {
        assert!(!should_log_scan_progress(999, 100_000, 1_000));
        assert!(should_log_scan_progress(1_000, 100_000, 1_000));
        assert!(should_log_scan_progress(100_000, 100_000, 1_000));
    }

    #[test]
    fn sampled_failures_log_only_the_first() {
        let failures = SampledFailures::new();
        assert!(failures.note());
        assert!(!failures.note());
        assert_eq!(failures.count(), 2);
    }
}
