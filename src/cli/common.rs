//! Small parsing and output helpers shared by CLI submodules.

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

/// Prints tab-separated rows.
///
/// # Arguments
///
/// - `rows`: cell rows to print.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// The current implementation never returns an error.
///
/// # Examples
///
/// ```text
/// print_rows(vec![vec!["a".into(), "b".into()]])
/// ```
pub(crate) fn print_rows(rows: Vec<Vec<String>>) -> anyhow::Result<()> {
    for row in rows {
        println!("{}", row.join("\t"));
    }
    Ok(())
}
