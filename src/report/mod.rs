//! Report generation and zip packaging.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde_json::{Map, Value, json};
use zip::{ZipWriter, write::SimpleFileOptions};

use crate::{
    config::{AppConfig, ReportFormat},
    db::Database,
    models::{Alert, PortAsset, UrlAsset, Vulnerability},
};

/// Report package metadata.
#[derive(Debug, Clone)]
pub struct ReportPackage {
    /// Path to generated zip archive.
    pub zip_path: PathBuf,
}

/// Builds a report directory and zip package for the specified or latest batch.
pub fn build_report_package(
    db: &Database,
    config: &AppConfig,
    batch: Option<&str>,
) -> anyhow::Result<ReportPackage> {
    let batch_id = match batch {
        Some(batch) => batch.to_string(),
        None => db.latest_batch_id()?,
    };
    let status = db.batch_status(Some(&batch_id))?;
    let alerts = db.list_alerts(&batch_id)?;
    let vulns = db.list_vulnerabilities(&batch_id)?;
    let urls = db.list_urls()?;
    let ports = db.list_open_ports()?;

    let report_dir = config.report.output_dir.join(&batch_id);
    fs::create_dir_all(&report_dir)
        .with_context(|| format!("failed to create {}", report_dir.display()))?;

    let tables = build_detail_tables(&alerts, &vulns, &urls, &ports);
    write_text(
        &report_dir.join("summary.md"),
        &render_markdown(
            &status,
            &alerts,
            &vulns,
            &urls,
            &ports,
            config.report.format,
        ),
    )?;
    write_detail_tables(&report_dir, config.report.format, &tables)?;

    let zip_path = config.report.output_dir.join(format!("{batch_id}.zip"));
    zip_dir(&report_dir, &zip_path)?;
    Ok(ReportPackage { zip_path })
}

/// Renders the human-readable monitoring summary.
fn render_markdown(
    status: &crate::models::BatchStatus,
    alerts: &[Alert],
    vulns: &[Vulnerability],
    urls: &[UrlAsset],
    open_ports: &[PortAsset],
    format: ReportFormat,
) -> String {
    let summary = ReportSummary::from_details(alerts, vulns, urls, open_ports);
    let vuln_types = render_counts(&summary.vulnerability_types);
    let dns_state = if summary.dns_changes == 0 {
        "无变化".to_string()
    } else {
        format!("有变化，{} 条", summary.dns_changes)
    };
    let detail_files = detail_file_description(format);
    format!(
        "# Watcher 资产监控报告\n\n\
         ## 批次信息\n\n\
         - 批次 ID: {}\n\
         - 执行状态: {}\n\
         - 开始时间: {}\n\
         - 结束时间: {}\n\n\
         ## 本次概览\n\n\
         - 告警总数: {}\n\
         - URL 资产总数: {}，其中基准 {} 个，非基准/发现 {} 个\n\
         - 当前开放端口总数: {}，其中基准 {} 个，非基准/新增发现 {} 个\n\
         - 本批次新增开放端口: {}\n\
         - 本批次关闭端口: {}\n\
         - 域名解析变化: {}\n\
         - 漏洞总数: {}\n\
         - 漏洞类型分布: {}\n\n\
         ## 重点关注\n\n\
         {}\n\n\
         ## 基准比较说明\n\n\
         - baseline import 或 baseline 资产管理命令导入的资产会被标记为基准资产。\n\
         - 非基准端口通常来自扫描中新发现的开放端口，建议优先确认是否符合预期。\n\
         - 非基准 URL 通常来自 Web 枚举、JS 解析或漏洞检测归并，建议结合明细文件进一步筛选。\n\n\
         ## 明细文件\n\n\
         {}\n",
        status.batch_id,
        status.status,
        status.started_at,
        status.ended_at.clone().unwrap_or_else(|| "-".to_string()),
        alerts.len(),
        summary.total_urls,
        summary.baseline_urls,
        summary.non_baseline_urls,
        summary.total_open_ports,
        summary.baseline_open_ports,
        summary.non_baseline_open_ports,
        summary.new_open_ports,
        summary.closed_ports,
        dns_state,
        vulns.len(),
        vuln_types,
        render_focus_table(&summary),
        detail_files
    )
}

/// Aggregated report summary derived from detailed rows.
#[derive(Debug, Default)]
struct ReportSummary {
    /// Total URL assets at report time.
    total_urls: usize,
    /// URL assets belonging to the imported baseline.
    baseline_urls: usize,
    /// URL assets discovered outside the imported baseline.
    non_baseline_urls: usize,
    /// Total currently open ports at report time.
    total_open_ports: usize,
    /// Open ports belonging to the imported baseline.
    baseline_open_ports: usize,
    /// Open ports discovered outside the imported baseline.
    non_baseline_open_ports: usize,
    /// Number of newly open port alerts in this batch.
    new_open_ports: usize,
    /// Number of closed port alerts in this batch.
    closed_ports: usize,
    /// Number of DNS resolution changes.
    dns_changes: usize,
    /// Vulnerability counts grouped by POC id.
    vulnerability_types: BTreeMap<String, usize>,
    /// Human-readable examples of newly open ports.
    new_open_port_examples: Vec<String>,
    /// Human-readable examples of currently open non-baseline ports.
    non_baseline_open_port_examples: Vec<String>,
    /// Human-readable examples of non-baseline URLs.
    non_baseline_url_examples: Vec<String>,
    /// Human-readable examples of DNS changes.
    dns_change_examples: Vec<String>,
    /// Human-readable examples of vulnerability findings.
    vulnerability_examples: Vec<String>,
}

impl ReportSummary {
    /// Builds an aggregate summary from alerts and vulnerability rows.
    fn from_details(
        alerts: &[Alert],
        vulns: &[Vulnerability],
        urls: &[UrlAsset],
        ports: &[PortAsset],
    ) -> Self {
        let total_urls = urls.len();
        let baseline_urls = urls.iter().filter(|url| url.is_baseline).count();
        let total_open_ports = ports.len();
        let baseline_open_ports = ports.iter().filter(|port| port.is_baseline).count();
        let mut summary = Self {
            total_urls,
            baseline_urls,
            non_baseline_urls: total_urls - baseline_urls,
            total_open_ports,
            baseline_open_ports,
            non_baseline_open_ports: total_open_ports - baseline_open_ports,
            ..Self::default()
        };
        for port in ports.iter().filter(|port| !port.is_baseline) {
            let ip = port.ip.as_deref().unwrap_or("-");
            push_example(
                &mut summary.non_baseline_open_port_examples,
                format!("{} {}:{}", port.system_name, ip, port.port),
            );
        }
        for url in urls.iter().filter(|url| !url.is_baseline) {
            push_example(
                &mut summary.non_baseline_url_examples,
                format!("{} {}", url.system_name, url.url),
            );
        }
        for alert in alerts {
            match alert.kind.as_str() {
                "port_change" if alert.new_value.as_deref() == Some("open") => {
                    summary.new_open_ports += 1;
                    push_example(&mut summary.new_open_port_examples, alert.subject.clone());
                }
                "port_change" if alert.new_value.as_deref() == Some("closed") => {
                    summary.closed_ports += 1;
                }
                "dns_change" => {
                    summary.dns_changes += 1;
                    let old_value = alert.old_value.as_deref().unwrap_or("-");
                    let new_value = alert.new_value.as_deref().unwrap_or("-");
                    push_example(
                        &mut summary.dns_change_examples,
                        format!("{}: {} -> {}", alert.subject, old_value, new_value),
                    );
                }
                _ => {}
            }
        }
        for vuln in vulns {
            *summary
                .vulnerability_types
                .entry(vuln.poc.clone())
                .or_insert(0) += 1;
            push_example(
                &mut summary.vulnerability_examples,
                format!("{} [{}] {}", vuln.url, vuln.severity, vuln.poc),
            );
        }
        summary
    }
}

/// Keeps summary examples short and readable.
fn push_example(values: &mut Vec<String>, value: String) {
    if values.len() < 5 {
        values.push(value);
    }
}

/// Renders a count map as Markdown-friendly text.
fn render_counts(values: &BTreeMap<String, usize>) -> String {
    if values.is_empty() {
        return "无".to_string();
    }
    values
        .iter()
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Renders a compact example list.
fn render_examples(values: &[String]) -> String {
    if values.is_empty() {
        "无".to_string()
    } else {
        values.join("; ")
    }
}

/// Renders focus items as a classified Markdown table.
fn render_focus_table(summary: &ReportSummary) -> String {
    let rows = [
        ("本批次新增开放端口", &summary.new_open_port_examples),
        (
            "当前非基准开放端口",
            &summary.non_baseline_open_port_examples,
        ),
        ("当前非基准 URL", &summary.non_baseline_url_examples),
        ("域名解析变化", &summary.dns_change_examples),
        ("漏洞", &summary.vulnerability_examples),
    ];
    let mut output = String::from("| 分类 | 重点信息 |\n|---|---|\n");
    for (category, examples) in rows {
        output.push_str(&format!(
            "| {} | {} |\n",
            markdown_escape(category),
            markdown_escape(&render_examples(examples))
        ));
    }
    output
}

/// Escapes text used inside Markdown table cells.
fn markdown_escape(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "<br>")
}

/// Writes text to a file.
fn write_text(path: &Path, content: &str) -> anyhow::Result<()> {
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// In-memory detail table used by all report output formats.
#[derive(Debug, Clone)]
struct ReportTable {
    /// Stable table name used as file name, JSON key and XLSX sheet name.
    name: &'static str,
    /// Header row.
    headers: Vec<&'static str>,
    /// Data rows.
    rows: Vec<Vec<String>>,
}

/// Builds all detail tables once so every output format has identical content.
fn build_detail_tables(
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
fn write_detail_tables(
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

/// Builds alert details.
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
                alert.created_at.to_rfc3339(),
            ]
        })
        .collect();
    ReportTable {
        name: "alerts",
        headers,
        rows,
    }
}

/// Builds vulnerability details.
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
                vuln.created_at.to_rfc3339(),
            ]
        })
        .collect();
    ReportTable {
        name: "vulnerabilities",
        headers,
        rows,
    }
}

/// Builds URL asset details.
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

/// Builds currently open port details.
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

/// Writes one CSV file per detail table.
fn write_csv_files(report_dir: &Path, tables: &[ReportTable]) -> anyhow::Result<()> {
    for table in tables {
        write_table_csv(&report_dir.join(format!("{}.csv", table.name)), table)?;
    }
    Ok(())
}

/// Writes one table to CSV.
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

/// Writes all detail tables to a single JSON file.
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

/// Writes all detail tables to an XLSX workbook.
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

/// Removes characters that are invalid in XML-backed XLSX strings.
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

/// Describes detail files included in the report package.
fn detail_file_description(format: ReportFormat) -> String {
    match format {
        ReportFormat::Xlsx => {
            "- details.xlsx: 包含 alerts、vulnerabilities、urls、open_ports 四个工作表，适合 Excel/WPS 查看、筛选和排序。".to_string()
        }
        ReportFormat::Json => {
            "- details.json: 包含 alerts、vulnerabilities、urls、open_ports 四组结构化明细，适合程序读取。".to_string()
        }
        ReportFormat::Csv => [
            "- alerts.csv: 资产变化、DNS 变化、端口变化和漏洞告警明细。",
            "- vulnerabilities.csv: 轻量 POC 漏洞发现明细。",
            "- urls.csv: 导入和发现的 URL 资产明细，baseline 列用于区分基准资产。",
            "- open_ports.csv: 当前开放 TCP 端口和服务指纹明细，baseline 列用于区分基准资产。",
        ]
        .join("\n"),
    }
}

/// Renders a boolean for human-friendly CSV output.
fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// Zips all files in a report directory.
fn zip_dir(source_dir: &Path, zip_path: &Path) -> anyhow::Result<()> {
    let file = File::create(zip_path)
        .with_context(|| format!("failed to create {}", zip_path.display()))?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for entry in fs::read_dir(source_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("report file has invalid name")?;
        zip.start_file(name, options)?;
        let mut input = File::open(&path)?;
        let mut buffer = Vec::new();
        input.read_to_end(&mut buffer)?;
        zip.write_all(&buffer)?;
    }
    zip.finish()?;
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
    fn describes_configured_detail_files() {
        assert!(detail_file_description(ReportFormat::Xlsx).contains("details.xlsx"));
        assert!(detail_file_description(ReportFormat::Json).contains("details.json"));
        assert!(detail_file_description(ReportFormat::Csv).contains("alerts.csv"));
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
