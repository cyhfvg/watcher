//! Configuration defaults and path expansion.

use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::local_time;

/// Returns the default number of IPs scanned at the same time during port scanning.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// The default concurrent IP count, `4`.
///
/// # Examples
///
/// ```text
/// let n = default_scan_ip_concurrency();
/// ```
pub(crate) fn default_scan_ip_concurrency() -> usize {
    4
}

/// Returns the default number of ports scanned at the same time for one IP.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// The default per-IP port concurrency, `4`.
///
/// # Examples
///
/// ```text
/// let n = default_scan_port_concurrency_per_ip();
/// ```
pub(crate) fn default_scan_port_concurrency_per_ip() -> usize {
    4
}

/// Returns the default display timezone, UTC+08:00.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// A copy of [`local_time::DEFAULT_TIMEZONE`].
///
/// # Examples
///
/// ```text
/// let tz = default_display_timezone();
/// ```
pub(crate) fn default_display_timezone() -> String {
    local_time::DEFAULT_TIMEZONE.to_string()
}

/// Returns the default SQLite database file path.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// `~/.config/watcher/watcher.db`.
///
/// # Examples
///
/// ```text
/// let path = default_database_path();
/// ```
pub(crate) fn default_database_path() -> PathBuf {
    PathBuf::from("~/.config/watcher/watcher.db")
}

/// Returns the default POC switch value.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// Enabled by default (`true`).
///
/// # Examples
///
/// ```text
/// let enabled = default_enabled();
/// ```
pub(crate) fn default_enabled() -> bool {
    true
}

/// Returns the default maximum number of URLs one POC checks in a batch.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// The default limit, `1000`.
///
/// # Examples
///
/// ```text
/// let n = default_poc_max_urls_per_batch();
/// ```
pub(crate) fn default_poc_max_urls_per_batch() -> usize {
    1_000
}

/// Returns the default maximum number of JavaScript files fetched for one URL.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// The default limit, `20`.
///
/// # Examples
///
/// ```text
/// let n = default_poc_max_js_files_per_url();
/// ```
pub(crate) fn default_poc_max_js_files_per_url() -> usize {
    20
}

/// Returns the default maximum number of source map candidates checked for one URL.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// The default limit, `20`.
///
/// # Examples
///
/// ```text
/// let n = default_poc_max_map_candidates_per_url();
/// ```
pub(crate) fn default_poc_max_map_candidates_per_url() -> usize {
    20
}

/// Returns the default nmap executable name used by detailed fingerprinting.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// `"nmap"`.
///
/// # Examples
///
/// ```text
/// let path = default_nmap_path();
/// ```
pub(crate) fn default_nmap_path() -> String {
    "nmap".to_string()
}

/// Returns the default timeout for one detailed fingerprint probe.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// The default timeout in milliseconds, `30000`.
///
/// # Examples
///
/// ```text
/// let ms = default_detailed_fingerprint_timeout_ms();
/// ```
pub(crate) fn default_detailed_fingerprint_timeout_ms() -> u64 {
    30_000
}

/// Returns the default number of nmap probes run at the same time.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// The default concurrency, `2`.
///
/// # Examples
///
/// ```text
/// let n = default_detailed_fingerprint_concurrency();
/// ```
pub(crate) fn default_detailed_fingerprint_concurrency() -> usize {
    2
}

/// Returns the default SMTP security mode. `auto` maps 465 to TLS and 587 to STARTTLS.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// `"auto"`.
///
/// # Examples
///
/// ```text
/// let mode = default_smtp_security();
/// ```
pub(crate) fn default_smtp_security() -> String {
    "auto".to_string()
}

/// Returns the default configuration file path.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// `$CONFIG_DIR/watcher/watcher.yml`.
///
/// # Errors
///
/// Returns an error when the user config directory cannot be located.
///
/// # Examples
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

/// Expands a leading `~` in a path.
///
/// A lone `~` is replaced with the user home directory; `~/...` becomes
/// `home/...`. Other paths are returned unchanged.
///
/// # Arguments
///
/// - `path`: path that may start with `~`
///
/// # Returns
///
/// The expanded path. Falls back to `~` or the original path when the home
/// directory cannot be resolved.
///
/// # Examples
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
