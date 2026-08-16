//! Small parsing helpers shared by CLI submodules.

use anyhow::Context;

/// Parses a CLI port value.
///
/// # Arguments
///
/// - `value`: port string.
///
/// # Returns
///
/// The parsed `u16` port.
///
/// # Errors
///
/// Returns an error when the string is not a valid `u16`.
///
/// # Examples
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
