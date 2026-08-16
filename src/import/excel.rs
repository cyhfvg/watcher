//! Excel asset importer.

use std::{collections::HashMap, path::Path};

use anyhow::Context;

use crate::db::{BaselineImportRow, BaselineImportSummary, Database};

/// Import counters returned after an Excel import.
pub type ImportSummary = BaselineImportSummary;

/// Imports watcher assets from the first Excel worksheet.
///
/// Required headers are `system`, `real_ip`, and `port`; optional headers are
/// `servername`, `servername_bind_ip`, and `url`. An Excel `id` column is
/// ignored.
///
/// # Arguments
///
/// - `db`: database used to write baseline assets.
/// - `path`: `.xlsx` file path.
///
/// # Returns
///
/// Import count summary.
///
/// # Errors
///
/// Returns an error if the workbook cannot be opened, a worksheet / required
/// header is missing, a port cell cannot be parsed, or the database write
/// fails.
///
/// # Examples
///
/// ```no_run
/// # use std::path::Path;
/// # use watcher::{db::Database, import::excel};
/// # fn demo(db: &Database, path: &Path) -> anyhow::Result<()> {
/// let summary = excel::import_excel(db, path)?;
/// println!("imported {}", summary.systems);
/// # Ok(())
/// # }
/// ```
pub fn import_excel(db: &Database, path: &Path) -> anyhow::Result<ImportSummary> {
    let workbook = umya_spreadsheet::reader::xlsx::read(path)
        .with_context(|| format!("failed to open workbook {}", path.display()))?;
    let worksheet = workbook
        .get_sheet_collection()
        .first()
        .context("workbook has no worksheet")?;
    let max_row = worksheet.get_highest_row();
    let max_column = worksheet.get_highest_column();
    anyhow::ensure!(max_row >= 1, "worksheet has no header row");

    let header = read_row(worksheet, 1, max_column);
    let indexes = header_indexes(header);
    require_header(&indexes, "system")?;

    let mut rows = Vec::new();
    for row_number in 2..=max_row {
        let row = read_row(worksheet, row_number, max_column);
        let system = cell(&row, &indexes, "system");
        if system.is_empty() {
            continue;
        }

        let servername = cell(&row, &indexes, "servername");
        let bind_ip = cell(&row, &indexes, "servername_bind_ip");
        let real_ip = cell(&row, &indexes, "real_ip");
        let port_text = cell(&row, &indexes, "port");
        let url = cell(&row, &indexes, "url");
        rows.push(BaselineImportRow {
            system,
            name: (!servername.is_empty()).then_some(servername),
            bind_ip: (!bind_ip.is_empty()).then_some(bind_ip),
            ip: (!real_ip.is_empty()).then_some(real_ip),
            ports: if port_text.is_empty() {
                Vec::new()
            } else {
                parse_ports(&port_text)?
            },
            url: (!url.is_empty()).then_some(url),
        });
    }

    db.import_baseline_rows(&rows, "imported")
}

/// Reads one worksheet row and trims every cell.
///
/// # Arguments
///
/// - `worksheet`: Excel worksheet.
/// - `row_number`: 1-based row number.
/// - `max_column`: highest column number to read.
///
/// # Returns
///
/// String values for each column in the row; empty cells become empty strings.
///
/// # Examples
///
/// ```text
/// let header = read_row(worksheet, 1, max_column);
/// ```
fn read_row(
    worksheet: &umya_spreadsheet::structs::Worksheet,
    row_number: u32,
    max_column: u32,
) -> Vec<String> {
    (1..=max_column)
        .map(|column| worksheet.get_value((column, row_number)).trim().to_string())
        .collect()
}

/// Builds a map from lowercase header names to column indexes.
///
/// # Arguments
///
/// - `header`: first-row cell text.
///
/// # Returns
///
/// `name -> index` map after empty headers are ignored.
///
/// # Examples
///
/// ```text
/// let indexes = header_indexes(header);
/// ```
fn header_indexes(header: Vec<String>) -> HashMap<String, usize> {
    header
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            let key = value.trim().to_ascii_lowercase();
            (!key.is_empty()).then_some((key, index))
        })
        .collect()
}

/// Confirms that a required header exists.
///
/// # Arguments
///
/// - `indexes`: header map.
/// - `name`: expected lowercase header name.
///
/// # Returns
///
/// `Ok(())` when the header is present.
///
/// # Errors
///
/// Returns an error if the column is missing.
///
/// # Examples
///
/// ```text
/// require_header(&indexes, "system")?;
/// ```
fn require_header(indexes: &HashMap<String, usize>, name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        indexes.contains_key(name),
        "missing required excel column `{name}`"
    );
    Ok(())
}

/// Reads a cell by header name and trims it.
///
/// # Arguments
///
/// - `row`: already-read row data.
/// - `indexes`: header map.
/// - `name`: column name.
///
/// # Returns
///
/// Cell text; missing columns or cells become an empty string.
///
/// # Examples
///
/// ```text
/// let system = cell(&row, &indexes, "system");
/// ```
fn cell(row: &[String], indexes: &HashMap<String, usize>, name: &str) -> String {
    indexes
        .get(name)
        .and_then(|index| row.get(*index))
        .cloned()
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Parses a port cell separated by commas, semicolons, slashes, or whitespace.
///
/// # Arguments
///
/// - `value`: port cell text.
///
/// # Returns
///
/// Parsed port list, in input order.
///
/// # Errors
///
/// Returns an error if any port token cannot be parsed.
///
/// # Examples
///
/// ```text
/// let ports = parse_ports("80,443/8080")?;
/// ```
fn parse_ports(value: &str) -> anyhow::Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in value
        .split([',', ';', '/', ' '])
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        ports.push(parse_port(part)?);
    }
    Ok(ports)
}

/// Parses one port token, including Excel integer forms such as `443.0`.
///
/// # Arguments
///
/// - `value`: single port text.
///
/// # Returns
///
/// `u16` port number.
///
/// # Errors
///
/// Returns an error if the value is not an integer, has a fractional part, or
/// is outside the `u16` range.
///
/// # Examples
///
/// ```text
/// let port = parse_port("443.0")?;
/// ```
fn parse_port(value: &str) -> anyhow::Result<u16> {
    if let Ok(port) = value.parse::<u16>() {
        return Ok(port);
    }
    let number = value
        .parse::<f64>()
        .with_context(|| format!("invalid port `{value}`"))?;
    anyhow::ensure!(
        number.fract() == 0.0 && (0.0..=u16::MAX as f64).contains(&number),
        "invalid port `{value}`"
    );
    Ok(number as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiple_ports() {
        assert_eq!(parse_ports("80,443/8080").unwrap(), vec![80, 443, 8080]);
    }

    #[test]
    fn parses_excel_integer_like_ports() {
        assert_eq!(parse_ports("80.0;443").unwrap(), vec![80, 443]);
    }
}
