//! Display-timezone formatting helpers for human-facing output.

use std::sync::{OnceLock, RwLock};

use chrono::{DateTime, FixedOffset, Utc};

/// Default display timezone: UTC+08:00.
pub const DEFAULT_TIMEZONE: &str = "+08:00";

static DISPLAY_OFFSET: OnceLock<RwLock<FixedOffset>> = OnceLock::new();

/// 配置面向人读输出使用的显示时区.
///
/// # 参数
///
/// - `timezone`: 时区字符串, 例如 `+08:00`, `UTC+8` 或 `Asia/Shanghai`.
///
/// # 返回
///
/// 解析并写入全局偏移成功时返回 `Ok(())`.
///
/// # Errors
///
/// 时区字符串无法解析, 或内部锁被毒化时返回错误.
///
/// # 示例
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

/// 把显示时区字符串解析为固定 UTC 偏移.
///
/// 支持 `Z` / `UTC`, `+08:00`, `-0530`, `UTC+8`, 以及若干东亚城市别名.
///
/// # 参数
///
/// - `timezone`: 待解析的时区文本.
///
/// # 返回
///
/// 对应的 [`FixedOffset`].
///
/// # Errors
///
/// 空字符串或无法识别的格式返回错误.
///
/// # 示例
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

/// 返回当前配置的显示时区, 格式为 RFC3339 偏移字符串.
///
/// # 参数
///
/// 无.
///
/// # 返回
///
/// 例如 `+08:00`. 读锁失败时回退到默认时区.
///
/// # 示例
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

/// 返回配置显示时区下的当前时间.
///
/// # 参数
///
/// 无.
///
/// # 返回
///
/// RFC3339 时间戳字符串.
///
/// # 示例
///
/// ```
/// let now = watcher::local_time::now_rfc3339();
/// assert!(now.contains('T'));
/// ```
pub fn now_rfc3339() -> String {
    Utc::now().with_timezone(&current_offset()).to_rfc3339()
}

/// 把 RFC3339 时间戳转换到配置显示时区.
///
/// # 参数
///
/// - `value`: RFC3339 时间戳.
///
/// # 返回
///
/// 转换后的 RFC3339 字符串; 解析失败时原样返回输入.
///
/// # 示例
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

/// 转换可选 RFC3339 时间戳; 缺省时返回 `-`.
///
/// # 参数
///
/// - `value`: 可选 RFC3339 时间戳.
///
/// # 返回
///
/// 转换后的本地时间, 或 `-`.
///
/// # 示例
///
/// ```
/// assert_eq!(watcher::local_time::optional_rfc3339_to_local(None), "-");
/// ```
pub fn optional_rfc3339_to_local(value: Option<&str>) -> String {
    value
        .map(rfc3339_to_local)
        .unwrap_or_else(|| "-".to_string())
}

/// 把 UTC 时间戳转换到配置显示时区.
///
/// # 参数
///
/// - `value`: UTC 时间.
///
/// # 返回
///
/// RFC3339 本地时间字符串.
///
/// # 示例
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

/// 返回进程内共享的显示时区锁.
///
/// # 参数
///
/// 无.
///
/// # 返回
///
/// 惰性初始化的 `RwLock<FixedOffset>` 静态引用.
///
/// # 示例
///
/// ```text
/// let offset = *display_offset().read().unwrap();
/// ```
fn display_offset() -> &'static RwLock<FixedOffset> {
    DISPLAY_OFFSET.get_or_init(|| RwLock::new(default_offset()))
}

/// 读取当前显示偏移; 锁毒化时回退到默认东八区.
///
/// # 参数
///
/// 无.
///
/// # 返回
///
/// 当前 [`FixedOffset`].
///
/// # 示例
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

/// 返回默认显示时区 UTC+08:00.
///
/// # 参数
///
/// 无.
///
/// # 返回
///
/// 东八区固定偏移.
///
/// # Panics
///
/// 偏移常量非法时 panic. 该常量在编译期已知合法.
///
/// # 示例
///
/// ```text
/// let offset = default_offset();
/// ```
fn default_offset() -> FixedOffset {
    FixedOffset::east_opt(8 * 3600).expect("valid default display timezone")
}

/// 解析 `+08:00`, `-0530` 或 `+8` 这类固定偏移.
///
/// # 参数
///
/// - `value`: 已去掉 `UTC` 前缀的偏移文本.
///
/// # 返回
///
/// 合法时返回 [`FixedOffset`], 否则 `None`.
///
/// # 示例
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

/// 把固定偏移格式化为 `+HH:MM`.
///
/// # 参数
///
/// - `offset`: 固定 UTC 偏移.
///
/// # 返回
///
/// RFC3339 风格的偏移字符串.
///
/// # 示例
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
