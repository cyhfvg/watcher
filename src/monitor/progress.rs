//! Shared aggregate scan progress helpers.

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
}
