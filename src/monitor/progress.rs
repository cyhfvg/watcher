//! Shared aggregate scan progress helpers.

/// Returns how often aggregate scan progress should be logged.
pub(crate) fn scan_progress_interval(total: usize) -> usize {
    match total {
        0..=100 => total.max(1),
        _ => (total / 100).max(100),
    }
}

/// Returns true when a completed-item count should emit an aggregate progress log.
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
