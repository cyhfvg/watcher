//! 配置默认值与路径展开.

use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::local_time;

/// 返回端口扫描时同时扫描的默认 IP 数.
///
/// # 参数
///
/// 无
///
/// # 返回
///
/// 默认并发 IP 数 `4`.
///
/// # 示例
///
/// ```text
/// let n = default_scan_ip_concurrency();
/// ```
pub(crate) fn default_scan_ip_concurrency() -> usize {
    4
}

/// 返回单 IP 同时扫描的默认端口数.
///
/// # 参数
///
/// 无
///
/// # 返回
///
/// 单 IP 默认端口并发数 `4`.
///
/// # 示例
///
/// ```text
/// let n = default_scan_port_concurrency_per_ip();
/// ```
pub(crate) fn default_scan_port_concurrency_per_ip() -> usize {
    4
}

/// 返回默认展示时区, 即 UTC+08:00.
///
/// # 参数
///
/// 无
///
/// # 返回
///
/// [`local_time::DEFAULT_TIMEZONE`] 的副本.
///
/// # 示例
///
/// ```text
/// let tz = default_display_timezone();
/// ```
pub(crate) fn default_display_timezone() -> String {
    local_time::DEFAULT_TIMEZONE.to_string()
}

/// 返回默认 SQLite 数据库文件路径.
///
/// # 参数
///
/// 无
///
/// # 返回
///
/// `~/.config/watcher/watcher.db`.
///
/// # 示例
///
/// ```text
/// let path = default_database_path();
/// ```
pub(crate) fn default_database_path() -> PathBuf {
    PathBuf::from("~/.config/watcher/watcher.db")
}

/// 返回 POC 开关的默认值.
///
/// # 参数
///
/// 无
///
/// # 返回
///
/// 默认启用 (`true`).
///
/// # 示例
///
/// ```text
/// let enabled = default_enabled();
/// ```
pub(crate) fn default_enabled() -> bool {
    true
}

/// 返回单个 POC 一批最多检查的默认 URL 数.
///
/// # 参数
///
/// 无
///
/// # 返回
///
/// 默认上限 `1000`.
///
/// # 示例
///
/// ```text
/// let n = default_poc_max_urls_per_batch();
/// ```
pub(crate) fn default_poc_max_urls_per_batch() -> usize {
    1_000
}

/// 返回检查单个 URL 时默认最多拉取的 JavaScript 文件数.
///
/// # 参数
///
/// 无
///
/// # 返回
///
/// 默认上限 `20`.
///
/// # 示例
///
/// ```text
/// let n = default_poc_max_js_files_per_url();
/// ```
pub(crate) fn default_poc_max_js_files_per_url() -> usize {
    20
}

/// 返回单个 URL 默认最多检查的 source map 候选数.
///
/// # 参数
///
/// 无
///
/// # 返回
///
/// 默认上限 `20`.
///
/// # 示例
///
/// ```text
/// let n = default_poc_max_map_candidates_per_url();
/// ```
pub(crate) fn default_poc_max_map_candidates_per_url() -> usize {
    20
}

/// 返回详细指纹探测使用的默认 nmap 可执行文件名.
///
/// # 参数
///
/// 无
///
/// # 返回
///
/// `"nmap"`.
///
/// # 示例
///
/// ```text
/// let path = default_nmap_path();
/// ```
pub(crate) fn default_nmap_path() -> String {
    "nmap".to_string()
}

/// 返回一次详细指纹探测的默认超时.
///
/// # 参数
///
/// 无
///
/// # 返回
///
/// 默认超时毫秒数 `30000`.
///
/// # 示例
///
/// ```text
/// let ms = default_detailed_fingerprint_timeout_ms();
/// ```
pub(crate) fn default_detailed_fingerprint_timeout_ms() -> u64 {
    30_000
}

/// 返回同时运行的默认 nmap 探测数.
///
/// # 参数
///
/// 无
///
/// # 返回
///
/// 默认并发数 `2`.
///
/// # 示例
///
/// ```text
/// let n = default_detailed_fingerprint_concurrency();
/// ```
pub(crate) fn default_detailed_fingerprint_concurrency() -> usize {
    2
}

/// 返回默认 SMTP 安全模式. `auto` 会把 465 映射为 TLS, 把 587 映射为 STARTTLS.
///
/// # 参数
///
/// 无
///
/// # 返回
///
/// `"auto"`.
///
/// # 示例
///
/// ```text
/// let mode = default_smtp_security();
/// ```
pub(crate) fn default_smtp_security() -> String {
    "auto".to_string()
}

/// 返回默认配置文件路径.
///
/// # 参数
///
/// 无
///
/// # 返回
///
/// `$CONFIG_DIR/watcher/watcher.yml`.
///
/// # Errors
///
/// 无法定位用户配置目录时返回错误.
///
/// # 示例
///
/// ```text
/// let path = default_config_path()?;
/// ```
pub(crate) fn default_config_path() -> anyhow::Result<PathBuf> {
    let dir = dirs::config_dir()
        .context("failed to locate user config directory")?
        .join("watcher");
    Ok(dir.join("watcher.yml"))
}

/// 展开路径中的前导 `~`.
///
/// `~` 单独出现时替换为用户主目录; `~/...` 替换为 `主目录/...`. 其它路径原样返回.
///
/// # 参数
///
/// - `path`: 可能含 `~` 前缀的路径
///
/// # 返回
///
/// 展开后的路径. 无法解析主目录时退回 `~` 或原路径.
///
/// # 示例
///
/// ```text
/// let expanded = expand_tilde(Path::new("~/watcher.yml"));
/// ```
pub(crate) fn expand_tilde(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    }
    if let Some(rest) = text.strip_prefix("~/") {
        return dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("~"))
            .join(rest);
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_tilde_prefix() {
        let expanded = expand_tilde(Path::new("~/watcher.yml"));
        assert!(expanded.ends_with("watcher.yml"));
        assert!(!expanded.to_string_lossy().starts_with("~/"));
    }
}
