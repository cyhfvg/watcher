//! Shared aggregate scan progress helpers.

/// 计算聚合扫描进度日志的间隔.
///
/// # 参数
///
/// - `total`: 待处理条目总数.
///
/// # 返回
///
/// 总数不超过 100 时每条都记; 更大时约为总数的 1%, 且至少 100.
///
/// # 示例
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

/// 判断已完成数量是否应输出聚合进度日志.
///
/// # 参数
///
/// - `completed`: 已处理条目数.
/// - `total`: 条目总数.
/// - `interval`: [`scan_progress_interval`] 算出的间隔.
///
/// # 返回
///
/// 全部完成, 或 `completed` 能被间隔整除时返回 `true`.
///
/// # 示例
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
