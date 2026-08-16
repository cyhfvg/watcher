//! CLI 子模块共用的小型解析辅助.

use anyhow::Context;

/// 解析 CLI 端口值.
///
/// # 参数
///
/// - `value`: 端口字符串.
///
/// # 返回
///
/// 解析成功的 `u16` 端口.
///
/// # Errors
///
/// 字符串不是合法 `u16` 时返回错误.
///
/// # 示例
///
/// ```text
/// parse_port("443") -> Ok(443)
/// parse_port("x") -> Err(...)
/// ```
pub(crate) fn parse_port(value: &str) -> anyhow::Result<u16> {
    value
        .parse::<u16>()
        .with_context(|| format!("invalid port {value}"))
}
