//! Display-timezone formatting helpers for human-facing output.

use std::sync::{OnceLock, RwLock};

use chrono::{DateTime, FixedOffset, Utc};

/// Default display timezone: UTC+08:00.
pub const DEFAULT_TIMEZONE: &str = "+08:00";

static DISPLAY_OFFSET: OnceLock<RwLock<FixedOffset>> = OnceLock::new();

/// Configures the timezone used by human-facing output.
pub fn configure(timezone: &str) -> anyhow::Result<()> {
    let offset = parse_timezone(timezone)?;
    let mut current = display_offset()
        .write()
        .map_err(|_| anyhow::anyhow!("display timezone lock poisoned"))?;
    *current = offset;
    Ok(())
}

/// Parses a display timezone string into a fixed UTC offset.
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
pub fn configured_timezone() -> String {
    display_offset()
        .read()
        .map(|offset| format_offset(*offset))
        .unwrap_or_else(|_| DEFAULT_TIMEZONE.to_string())
}

/// Returns the current time in the configured display timezone.
pub fn now_rfc3339() -> String {
    Utc::now().with_timezone(&current_offset()).to_rfc3339()
}

/// Converts an RFC3339 timestamp to the configured timezone for display.
pub fn rfc3339_to_local(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&current_offset()).to_rfc3339())
        .unwrap_or_else(|_| value.to_string())
}

/// Converts an optional RFC3339 timestamp to display time, using `-` when absent.
pub fn optional_rfc3339_to_local(value: Option<&str>) -> String {
    value
        .map(rfc3339_to_local)
        .unwrap_or_else(|| "-".to_string())
}

/// Converts a UTC timestamp to the configured timezone for display.
pub fn utc_to_local(value: &DateTime<Utc>) -> String {
    value.with_timezone(&current_offset()).to_rfc3339()
}

fn display_offset() -> &'static RwLock<FixedOffset> {
    DISPLAY_OFFSET.get_or_init(|| RwLock::new(default_offset()))
}

fn current_offset() -> FixedOffset {
    display_offset()
        .read()
        .map(|offset| *offset)
        .unwrap_or_else(|_| default_offset())
}

fn default_offset() -> FixedOffset {
    FixedOffset::east_opt(8 * 3600).expect("valid default display timezone")
}

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

fn format_offset(offset: FixedOffset) -> String {
    let seconds = offset.local_minus_utc();
    let sign = if seconds >= 0 { '+' } else { '-' };
    let absolute = seconds.abs();
    format!("{sign}{:02}:{:02}", absolute / 3600, (absolute % 3600) / 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_display_timezones() {
        assert_eq!(format_offset(parse_timezone("+08:00").unwrap()), "+08:00");
        assert_eq!(format_offset(parse_timezone("UTC+8").unwrap()), "+08:00");
        assert_eq!(format_offset(parse_timezone("-0530").unwrap()), "-05:30");
        assert_eq!(
            format_offset(parse_timezone("Asia/Shanghai").unwrap()),
            "+08:00"
        );
    }
}
