//! Display-timezone formatting helpers for human-facing output.

use std::sync::{OnceLock, RwLock};

use chrono::{DateTime, FixedOffset, Utc};

/// Default display timezone: UTC+08:00.
pub const DEFAULT_TIMEZONE: &str = "+08:00";

static DISPLAY_OFFSET: OnceLock<RwLock<FixedOffset>> = OnceLock::new();

/// Configures the display timezone used for human-facing output.
///
/// # Arguments
///
/// - `timezone`: timezone string such as `+08:00`, `UTC+8`, or `Asia/Shanghai`.
///
/// # Returns
///
/// `Ok(())` after the string is parsed and written to the global offset.
///
/// # Errors
///
/// Returns an error if the timezone string cannot be parsed or the internal
/// lock is poisoned.
///
/// # Examples
///
/// ```
/// watcher::local_time::configure("+08:00")?;
/// assert_eq!(watcher::local_time::configured_timezone(), "+08:00");
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn configure(timezone: &str) -> anyhow::Result<()> {
    let offset = parse_timezone(timezone)?;
    let mut current = display_offset()
        .write()
        .map_err(|_| anyhow::anyhow!("display timezone lock poisoned"))?;
    *current = offset;
    Ok(())
}

/// Parses a display timezone string into a fixed UTC offset.
///
/// Accepts `Z` / `UTC`, `+08:00`, `-0530`, `UTC+8`, and a few East-Asia city
/// aliases.
///
/// # Arguments
///
/// - `timezone`: timezone text to parse.
///
/// # Returns
///
/// The matching [`FixedOffset`].
///
/// # Errors
///
/// Returns an error for an empty string or an unrecognized format.
///
/// # Examples
///
/// ```
/// let offset = watcher::local_time::parse_timezone("UTC+8")?;
/// assert_eq!(offset.local_minus_utc(), 8 * 3600);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn parse_timezone(timezone: &str) -> anyhow::Result<FixedOffset> {
    let value = timezone.trim();
    anyhow::ensure!(!value.is_empty(), "display timezone must not be empty");
    let normalized = match value.to_ascii_uppercase().as_str() {
        "Z" | "UTC" => "+00:00",
        "ASIA/SHANGHAI" | "ASIA/CHONGQING" | "ASIA/HONG_KONG" | "ASIA/TAIPEI" => "+08:00",
        _ => value
            .strip_prefix("UTC")
            .or_else(|| value.strip_prefix("utc"))
            .unwrap_or(value),
    };
    parse_fixed_offset(normalized).ok_or_else(|| {
        anyhow::anyhow!("invalid display timezone `{timezone}`; use +08:00, -05:30, UTC+8, or UTC")
    })
}

/// Returns the configured display timezone as an RFC3339 offset string.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// For example `+08:00`. Falls back to the default timezone if the read lock
/// fails.
///
/// # Examples
///
/// ```
/// watcher::local_time::configure("+08:00")?;
/// assert_eq!(watcher::local_time::configured_timezone(), "+08:00");
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn configured_timezone() -> String {
    display_offset()
        .read()
        .map(|offset| format_offset(*offset))
        .unwrap_or_else(|_| DEFAULT_TIMEZONE.to_string())
}

/// Returns the current time in the configured display timezone.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// RFC3339 timestamp string.
///
/// # Examples
///
/// ```
/// let now = watcher::local_time::now_rfc3339();
/// assert!(now.contains('T'));
/// ```
pub fn now_rfc3339() -> String {
    Utc::now().with_timezone(&current_offset()).to_rfc3339()
}

/// Converts an RFC3339 timestamp into the configured display timezone.
///
/// # Arguments
///
/// - `value`: RFC3339 timestamp.
///
/// # Returns
///
/// Converted RFC3339 string; returns the input unchanged if parsing fails.
///
/// # Examples
///
/// ```
/// watcher::local_time::configure("+08:00")?;
/// let local = watcher::local_time::rfc3339_to_local("2024-01-01T00:00:00Z");
/// assert!(local.contains("+08:00"));
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn rfc3339_to_local(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&current_offset()).to_rfc3339())
        .unwrap_or_else(|_| value.to_string())
}

/// Converts an optional RFC3339 timestamp; missing values become `-`.
///
/// # Arguments
///
/// - `value`: optional RFC3339 timestamp.
///
/// # Returns
///
/// Converted local time, or `-`.
///
/// # Examples
///
/// ```
/// assert_eq!(watcher::local_time::optional_rfc3339_to_local(None), "-");
/// ```
pub fn optional_rfc3339_to_local(value: Option<&str>) -> String {
    value
        .map(rfc3339_to_local)
        .unwrap_or_else(|| "-".to_string())
}

/// Converts a UTC timestamp into the configured display timezone.
///
/// # Arguments
///
/// - `value`: UTC time.
///
/// # Returns
///
/// RFC3339 local-time string.
///
/// # Examples
///
/// ```
/// use chrono::Utc;
/// watcher::local_time::configure("+08:00")?;
/// let local = watcher::local_time::utc_to_local(&Utc::now());
/// assert!(local.contains("+08:00"));
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn utc_to_local(value: &DateTime<Utc>) -> String {
    value.with_timezone(&current_offset()).to_rfc3339()
}

/// Returns the process-wide display timezone lock.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// Static reference to the lazily initialized `RwLock<FixedOffset>`.
///
/// # Examples
///
/// ```text
/// let offset = *display_offset().read().unwrap();
/// ```
fn display_offset() -> &'static RwLock<FixedOffset> {
    DISPLAY_OFFSET.get_or_init(|| RwLock::new(default_offset()))
}

/// Reads the current display offset; falls back to UTC+08:00 if the lock is
/// poisoned.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// Current [`FixedOffset`].
///
/// # Examples
///
/// ```text
/// let offset = current_offset();
/// ```
fn current_offset() -> FixedOffset {
    display_offset()
        .read()
        .map(|offset| *offset)
        .unwrap_or_else(|_| default_offset())
}

/// Returns the default display timezone UTC+08:00.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// Fixed offset for UTC+08:00.
///
/// # Panics
///
/// Panics if the offset constant is invalid. The constant is known valid at
/// compile time.
///
/// # Examples
///
/// ```text
/// let offset = default_offset();
/// ```
fn default_offset() -> FixedOffset {
    FixedOffset::east_opt(8 * 3600).expect("valid default display timezone")
}

/// Parses a fixed offset such as `+08:00`, `-0530`, or `+8`.
///
/// # Arguments
///
/// - `value`: offset text with any `UTC` prefix already stripped.
///
/// # Returns
///
/// [`FixedOffset`] when valid; otherwise `None`.
///
/// # Examples
///
/// ```text
/// let offset = parse_fixed_offset("+08:00");
/// ```
fn parse_fixed_offset(value: &str) -> Option<FixedOffset> {
    let (sign, rest) = match value.as_bytes().first().copied() {
        Some(b'+') => (1, &value[1..]),
        Some(b'-') => (-1, &value[1..]),
        _ => return None,
    };
    let (hours, minutes) = if let Some((hours, minutes)) = rest.split_once(':') {
        (hours.parse::<i32>().ok()?, minutes.parse::<i32>().ok()?)
    } else if rest.len() <= 2 {
        (rest.parse::<i32>().ok()?, 0)
    } else if rest.len() == 4 {
        (
            rest[..2].parse::<i32>().ok()?,
            rest[2..].parse::<i32>().ok()?,
        )
    } else {
        return None;
    };
    if hours > 23 || minutes > 59 {
        return None;
    }
    FixedOffset::east_opt(sign * (hours * 3600 + minutes * 60))
}

/// Formats a fixed offset as `+HH:MM`.
///
/// # Arguments
///
/// - `offset`: fixed UTC offset.
///
/// # Returns
///
/// RFC3339-style offset string.
///
/// # Examples
///
/// ```text
/// let text = format_offset(offset);
/// ```
fn format_offset(offset: FixedOffset) -> String {
    let seconds = offset.local_minus_utc();
    let sign = if seconds >= 0 { '+' } else { '-' };
    let absolute = seconds.abs();
    format!("{sign}{:02}:{:02}", absolute / 3600, (absolute % 3600) / 60)
}
