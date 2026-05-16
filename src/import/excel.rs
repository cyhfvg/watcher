//! Excel asset importer.

use std::{collections::HashMap, path::Path};

use anyhow::Context;

use crate::db::Database;

/// Import counters returned after an Excel import.
#[derive(Debug, Default, Clone, Copy)]
pub struct ImportSummary {
    /// Number of business-system rows processed.
    pub systems: usize,
    /// Number of domain names imported.
    pub names: usize,
    /// Number of IP addresses imported.
    pub ips: usize,
    /// Number of ports imported.
    pub ports: usize,
    /// Number of URLs imported.
    pub urls: usize,
}

/// Imports watcher assets from the first worksheet of an Excel file.
///
/// Required headers are `system`, `real_ip`, and `port`; optional headers are
/// `servername`, `servername_bind_ip`, and `url`. The Excel `id` column is ignored.
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

    let mut summary = ImportSummary::default();
    for row_number in 2..=max_row {
        let row = read_row(worksheet, row_number, max_column);
        let system = cell(&row, &indexes, "system");
        if system.is_empty() {
            continue;
        }
        summary.systems += 1;
        let system_id = db.upsert_system(&system)?;

        let servername = cell(&row, &indexes, "servername");
        let bind_ip = cell(&row, &indexes, "servername_bind_ip");
        if !servername.is_empty() {
            let domain_id = db.upsert_domain(
                &system_id,
                &servername,
                (!bind_ip.is_empty()).then_some(bind_ip.as_str()),
            )?;
            db.set_domain_baseline_by_id(&domain_id, true)?;
            summary.names += 1;
        }

        let real_ip = cell(&row, &indexes, "real_ip");
        let ip_id = if real_ip.is_empty() {
            None
        } else {
            summary.ips += 1;
            let ip_id = db.upsert_ip(&system_id, &real_ip, "imported")?;
            db.set_ip_baseline_by_id(&ip_id, true)?;
            Some(ip_id)
        };

        let port_text = cell(&row, &indexes, "port");
        if !port_text.is_empty() {
            for port in parse_ports(&port_text)? {
                let port_id = db.upsert_port(&system_id, ip_id.as_deref(), port, "imported")?;
                db.set_port_baseline_by_id(&port_id, true)?;
                summary.ports += 1;
            }
        }

        let url = cell(&row, &indexes, "url");
        if !url.is_empty() {
            let url_id = db.upsert_url(&system_id, &url, "imported", None, 10)?;
            db.set_url_baseline_by_id(&url_id, true)?;
            summary.urls += 1;
        }
    }

    Ok(summary)
}

/// Reads a worksheet row as trimmed string values.
fn read_row(
    worksheet: &umya_spreadsheet::structs::Worksheet,
    row_number: u32,
    max_column: u32,
) -> Vec<String> {
    (1..=max_column)
        .map(|column| worksheet.get_value((column, row_number)).trim().to_string())
        .collect()
}

/// Builds a lowercase header-name to column-index map.
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

/// Ensures an expected header exists.
fn require_header(indexes: &HashMap<String, usize>, name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        indexes.contains_key(name),
        "missing required excel column `{name}`"
    );
    Ok(())
}

/// Reads a named cell from a row.
fn cell(row: &[String], indexes: &HashMap<String, usize>, name: &str) -> String {
    indexes
        .get(name)
        .and_then(|index| row.get(*index))
        .cloned()
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Parses a comma-separated or slash-separated port cell.
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

/// Parses one port token, accepting Excel integer-like values such as `443.0`.
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
