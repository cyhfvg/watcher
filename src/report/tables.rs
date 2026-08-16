//! Builds report detail tables and writes them in multiple formats.

use std::{fs, path::Path};

use anyhow::Context;
use serde_json::{Map, Value, json};

use crate::{
    config::ReportFormat,
    local_time,
    models::{Alert, PortAsset, UrlAsset, Vulnerability},
};

/// In-memory detail table shared by every report output format.
#[derive(Debug, Clone)]
pub(crate) struct ReportTable {
    /// Stable table name used as the file name, JSON key, and XLSX sheet name.
    name: &'static str,
    /// Header row.
    headers: Vec<&'static str>,
    /// Data rows.
    rows: Vec<Vec<String>>,
}

/// Builds every detail table once so all output formats share the same content.
///
/// # Arguments
/// - `alerts`: alerts for this batch
/// - `vulns`: vulnerabilities for this batch
/// - `urls`: current URL assets
/// - `ports`: current open ports
///
/// # Returns
/// The alerts, vulnerabilities, URLs, and open-ports tables
///
/// # Examples
///
/// ```text
/// let tables = build_detail_tables(&alerts, &vulns, &urls, &ports);
/// ```
pub(crate) fn build_detail_tables(
    alerts: &[Alert],
    vulns: &[Vulnerability],
    urls: &[UrlAsset],
    ports: &[PortAsset],
) -> Vec<ReportTable> {
    vec![
        build_alerts_table(alerts),
        build_vulnerabilities_table(vulns),
        build_urls_table(urls),
        build_open_ports_table(ports),
    ]
}

/// Writes detail tables in the configured format.
///
/// # Arguments
/// - `report_dir`: report output directory
/// - `format`: detail file format
/// - `tables`: already built detail tables
///
/// # Returns
/// `()` when writing succeeds
///
/// # Errors
/// Returns an error when a destination file cannot be created or written.
///
/// # Examples
///
/// ```text
/// write_detail_tables(&report_dir, format, &tables)?;
/// ```
pub(crate) fn write_detail_tables(
    report_dir: &Path,
    format: ReportFormat,
    tables: &[ReportTable],
) -> anyhow::Result<()> {
    match format {
        ReportFormat::Xlsx => write_xlsx(&report_dir.join("details.xlsx"), tables),
        ReportFormat::Json => write_json(&report_dir.join("details.json"), tables),
        ReportFormat::Csv => write_csv_files(report_dir, tables),
    }
}

/// Builds the alerts detail table.
///
/// # Arguments
/// - `alerts`: alerts for this batch
///
/// # Returns
/// A [`ReportTable`] named `alerts`
///
/// # Examples
///
/// ```text
/// let table = build_alerts_table(&alerts);
/// ```
fn build_alerts_table(alerts: &[Alert]) -> ReportTable {
    let headers = vec![
        "id",
        "batch_id",
        "system_name",
        "kind",
        "severity",
        "subject",
        "old_value",
        "new_value",
        "details",
        "created_at",
    ];
    let rows = alerts
        .iter()
        .map(|alert| {
            vec![
                alert.id.clone(),
                alert.batch_id.clone(),
                alert.system_name.clone().unwrap_or_default(),
                alert.kind.clone(),
                alert.severity.clone(),
                alert.subject.clone(),
                alert.old_value.clone().unwrap_or_default(),
                alert.new_value.clone().unwrap_or_default(),
                alert.details.clone().unwrap_or_default(),
                local_time::utc_to_local(&alert.created_at),
            ]
        })
        .collect();
    ReportTable {
        name: "alerts",
        headers,
        rows,
    }
}

/// Builds the vulnerabilities detail table.
///
/// # Arguments
/// - `vulns`: vulnerabilities for this batch
///
/// # Returns
/// A [`ReportTable`] named `vulnerabilities`
///
/// # Examples
///
/// ```text
/// let table = build_vulnerabilities_table(&vulns);
/// ```
fn build_vulnerabilities_table(vulns: &[Vulnerability]) -> ReportTable {
    let headers = vec![
        "id",
        "batch_id",
        "system_name",
        "url",
        "poc",
        "severity",
        "evidence",
        "created_at",
    ];
    let rows = vulns
        .iter()
        .map(|vuln| {
            vec![
                vuln.id.clone(),
                vuln.batch_id.clone(),
                vuln.system_name.clone(),
                vuln.url.clone(),
                vuln.poc.clone(),
                vuln.severity.clone(),
                vuln.evidence.clone(),
                local_time::utc_to_local(&vuln.created_at),
            ]
        })
        .collect();
    ReportTable {
        name: "vulnerabilities",
        headers,
        rows,
    }
}

/// Builds the URL-asset detail table.
///
/// # Arguments
/// - `urls`: current URL assets
///
/// # Returns
/// A [`ReportTable`] named `urls`
///
/// # Examples
///
/// ```text
/// let table = build_urls_table(&urls);
/// ```
fn build_urls_table(urls: &[UrlAsset]) -> ReportTable {
    let headers = vec![
        "id",
        "system_name",
        "url",
        "source",
        "status_code",
        "value_score",
        "baseline",
    ];
    let rows = urls
        .iter()
        .map(|url| {
            vec![
                url.id.clone(),
                url.system_name.clone(),
                url.url.clone(),
                url.source.clone(),
                url.status_code
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                url.value_score.to_string(),
                bool_text(url.is_baseline).to_string(),
            ]
        })
        .collect();
    ReportTable {
        name: "urls",
        headers,
        rows,
    }
}

/// Builds the current open-ports detail table.
///
/// # Arguments
/// - `ports`: current open ports
///
/// # Returns
/// A [`ReportTable`] named `open_ports`
///
/// # Examples
///
/// ```text
/// let table = build_open_ports_table(&ports);
/// ```
fn build_open_ports_table(ports: &[PortAsset]) -> ReportTable {
    let headers = vec![
        "id",
        "system_name",
        "ip_id",
        "ip",
        "port",
        "state",
        "service",
        "fingerprint",
        "is_web",
        "scheme",
        "baseline",
    ];
    let rows = ports
        .iter()
        .map(|port| {
            vec![
                port.id.clone(),
                port.system_name.clone(),
                port.ip_id.clone().unwrap_or_default(),
                port.ip.clone().unwrap_or_default(),
                port.port.to_string(),
                port.state.clone(),
                port.service.clone().unwrap_or_default(),
                port.fingerprint.clone().unwrap_or_default(),
                bool_text(port.is_web).to_string(),
                port.scheme.clone().unwrap_or_default(),
                bool_text(port.is_baseline).to_string(),
            ]
        })
        .collect();
    ReportTable {
        name: "open_ports",
        headers,
        rows,
    }
}

/// Writes one CSV file for each detail table.
///
/// # Arguments
/// - `report_dir`: report output directory
/// - `tables`: detail tables to write
///
/// # Returns
/// `()` when writing succeeds
///
/// # Errors
/// Returns an error when any CSV cannot be created or written.
///
/// # Examples
///
/// ```text
/// write_csv_files(&report_dir, &tables)?;
/// ```
fn write_csv_files(report_dir: &Path, tables: &[ReportTable]) -> anyhow::Result<()> {
    for table in tables {
        write_table_csv(&report_dir.join(format!("{}.csv", table.name)), table)?;
    }
    Ok(())
}

/// Writes one table as CSV.
///
/// # Arguments
/// - `path`: destination CSV path
/// - `table`: detail table to write
///
/// # Returns
/// `()` when writing succeeds
///
/// # Errors
/// Returns an error when the CSV cannot be created, written, or flushed.
///
/// # Examples
///
/// ```text
/// write_table_csv(&path, &table)?;
/// ```
fn write_table_csv(path: &Path, table: &ReportTable) -> anyhow::Result<()> {
    let mut writer = csv::Writer::from_path(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    writer.write_record(&table.headers)?;
    for row in &table.rows {
        writer.write_record(row)?;
    }
    writer.flush()?;
    Ok(())
}

/// Writes every detail table into a single JSON file.
///
/// # Arguments
/// - `path`: destination JSON path
/// - `tables`: detail tables to write
///
/// # Returns
/// `()` when writing succeeds
///
/// # Errors
/// Returns an error when JSON serialization or file writing fails.
///
/// # Examples
///
/// ```text
/// write_json(&path, &tables)?;
/// ```
fn write_json(path: &Path, tables: &[ReportTable]) -> anyhow::Result<()> {
    let mut root = Map::new();
    for table in tables {
        let rows = table
            .rows
            .iter()
            .map(|row| {
                let mut object = Map::new();
                for (index, header) in table.headers.iter().enumerate() {
                    object.insert(
                        (*header).to_string(),
                        Value::String(row.get(index).cloned().unwrap_or_default()),
                    );
                }
                Value::Object(object)
            })
            .collect::<Vec<_>>();
        root.insert(table.name.to_string(), Value::Array(rows));
    }
    write_text(path, &serde_json::to_string_pretty(&json!(root))?)?;
    Ok(())
}

/// Writes every detail table into an XLSX workbook.
///
/// # Arguments
/// - `path`: destination XLSX path
/// - `tables`: detail tables to write
///
/// # Returns
/// `()` when writing succeeds
///
/// # Errors
/// Returns an error when a worksheet cannot be created or the XLSX cannot be written.
///
/// # Examples
///
/// ```text
/// write_xlsx(&path, &tables)?;
/// ```
fn write_xlsx(path: &Path, tables: &[ReportTable]) -> anyhow::Result<()> {
    let mut book = umya_spreadsheet::new_file_empty_worksheet();
    for table in tables {
        let sheet = book.new_sheet(table.name).map_err(|error| {
            anyhow::anyhow!("failed to create xlsx sheet {}: {error}", table.name)
        })?;
        for (column_index, header) in table.headers.iter().enumerate() {
            sheet
                .get_cell_mut(((column_index + 1) as u32, 1_u32))
                .set_value(*header);
        }
        for (row_index, row) in table.rows.iter().enumerate() {
            for (column_index, value) in row.iter().enumerate() {
                sheet
                    .get_cell_mut(((column_index + 1) as u32, (row_index + 2) as u32))
                    .set_value(sanitize_xlsx_text(value));
            }
        }
    }
    umya_spreadsheet::writer::xlsx::write(&book, path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Strips characters that are illegal in XML-based XLSX strings.
///
/// # Arguments
/// - `value`: original cell text
///
/// # Returns
/// Text that can be written to XLSX
///
/// # Examples
///
/// ```text
/// let safe = sanitize_xlsx_text("ok\u{0}bad");
/// ```
fn sanitize_xlsx_text(value: &str) -> String {
    value
        .chars()
        .filter(|ch| {
            matches!(*ch, '\u{9}' | '\u{A}' | '\u{D}')
                || ('\u{20}'..='\u{D7FF}').contains(ch)
                || ('\u{E000}'..='\u{FFFD}').contains(ch)
        })
        .collect()
}

/// Renders a boolean as readable CSV text.
///
/// # Arguments
/// - `value`: boolean value
///
/// # Returns
/// `"true"` or `"false"`
///
/// # Examples
///
/// ```text
/// let text = bool_text(url.is_baseline);
/// ```
fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// Writes text to a file.
///
/// # Arguments
/// - `path`: destination file path
/// - `content`: text to write
///
/// # Returns
/// `()` when writing succeeds
///
/// # Errors
/// Returns an error when the file cannot be created or written.
///
/// # Examples
///
/// ```text
/// write_text(&path, &markdown)?;
/// ```
pub(crate) fn write_text(path: &Path, content: &str) -> anyhow::Result<()> {
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_xlsx_text() {
        assert_eq!(sanitize_xlsx_text("ok\u{0}bad"), "okbad");
        assert_eq!(sanitize_xlsx_text("a&b<c>\"'"), "a&b<c>\"'");
    }

    #[test]
    fn writes_xlsx_with_readable_sheets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("details.xlsx");
        let tables = vec![
            ReportTable {
                name: "alerts",
                headers: vec!["system_name", "subject"],
                rows: vec![vec!["core".to_string(), "dns".to_string()]],
            },
            ReportTable {
                name: "open_ports",
                headers: vec!["system_name", "ip", "port"],
                rows: vec![vec![
                    "core".to_string(),
                    "10.0.0.1".to_string(),
                    "443".to_string(),
                ]],
            },
        ];
        write_xlsx(&path, &tables).unwrap();

        let workbook = umya_spreadsheet::reader::xlsx::read(&path).unwrap();
        assert!(workbook.get_sheet_by_name("alerts").is_some());
        let sheet = workbook.get_sheet_by_name("open_ports").unwrap();
        assert_eq!(sheet.get_value((1, 1)), "system_name");
        assert_eq!(sheet.get_value((3, 2)), "443");
    }
}
