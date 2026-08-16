//! Monitoring-summary Markdown rendering.

use std::collections::BTreeMap;

use crate::{
    config::ReportFormat,
    local_time,
    models::{Alert, PortAsset, UrlAsset, Vulnerability},
};

/// Renders a human-readable monitoring-summary Markdown document.
///
/// # Arguments
/// - `status`: batch execution status
/// - `alerts`: alerts for this batch
/// - `vulns`: vulnerabilities for this batch
/// - `urls`: current URL assets
/// - `open_ports`: current open ports
/// - `format`: detail-file format, used to describe attachments
///
/// # Returns
/// The complete `summary.md` text
///
/// # Examples
///
/// ```text
/// let markdown = render_markdown(&status, &alerts, &vulns, &urls, &ports, format);
/// ```
pub(crate) fn render_markdown(
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
        local_time::rfc3339_to_local(&status.started_at),
        local_time::optional_rfc3339_to_local(status.ended_at.as_deref()),
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

/// Report summary aggregated from detail rows.
#[derive(Debug, Default)]
struct ReportSummary {
    /// Total URL assets at report time.
    total_urls: usize,
    /// URL assets that belong to the imported baseline.
    baseline_urls: usize,
    /// URL assets discovered outside the baseline.
    non_baseline_urls: usize,
    /// Total currently open ports at report time.
    total_open_ports: usize,
    /// Open ports that belong to the imported baseline.
    baseline_open_ports: usize,
    /// Open ports discovered outside the baseline.
    non_baseline_open_ports: usize,
    /// New-open-port alerts in this batch.
    new_open_ports: usize,
    /// Closed-port alerts in this batch.
    closed_ports: usize,
    /// DNS-resolution change count.
    dns_changes: usize,
    /// Vulnerability counts grouped by POC identifier.
    vulnerability_types: BTreeMap<String, usize>,
    /// Readable examples of newly opened ports.
    new_open_port_examples: Vec<String>,
    /// Readable examples of current non-baseline open ports.
    non_baseline_open_port_examples: Vec<String>,
    /// Readable examples of non-baseline URLs.
    non_baseline_url_examples: Vec<String>,
    /// Readable examples of DNS changes.
    dns_change_examples: Vec<String>,
    /// Readable examples of vulnerability findings.
    vulnerability_examples: Vec<String>,
}

impl ReportSummary {
    /// Builds an aggregated summary from alerts, vulnerabilities, and assets.
    ///
    /// # Arguments
    /// - `alerts`: alerts for this batch
    /// - `vulns`: vulnerabilities for this batch
    /// - `urls`: current URL assets
    /// - `ports`: current open ports
    ///
    /// # Returns
    /// A populated [`ReportSummary`]
    ///
    /// # Examples
    ///
    /// ```text
    /// let summary = ReportSummary::from_details(&alerts, &vulns, &urls, &ports);
    /// ```
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
                    summary.new_open_ports += alert_port_count(alert);
                    for example in alert_port_examples(alert) {
                        push_example(&mut summary.new_open_port_examples, example);
                    }
                }
                "port_change" if alert.new_value.as_deref() == Some("closed") => {
                    summary.closed_ports += alert_port_count(alert);
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

/// Counts ports encoded in an IP-level `port_change` alert.
///
/// # Arguments
/// - `alert`: port-change alert
///
/// # Returns
/// The parsed port count; `1` when parsing fails
///
/// # Examples
///
/// ```text
/// let count = alert_port_count(&alert);
/// ```
fn alert_port_count(alert: &Alert) -> usize {
    parse_alert_ports(alert.details.as_deref())
        .map(|ports| ports.len().max(1))
        .unwrap_or(1)
}

/// Builds `ip:port` examples from an aggregated port-change alert.
///
/// # Arguments
/// - `alert`: port-change alert
///
/// # Returns
/// A readable `ip:port` list; falls back to the alert subject when parsing fails
///
/// # Examples
///
/// ```text
/// let examples = alert_port_examples(&alert);
/// ```
fn alert_port_examples(alert: &Alert) -> Vec<String> {
    match parse_alert_ports(alert.details.as_deref()) {
        Some(ports) if !ports.is_empty() => ports
            .into_iter()
            .map(|port| format!("{}:{port}", alert.subject))
            .collect(),
        _ => vec![alert.subject.clone()],
    }
}

/// Parses `{"count":N,"ports":[...]}` from alert details.
///
/// # Arguments
/// - `details`: alert JSON details
///
/// # Returns
/// The port list when parsing succeeds, otherwise `None`
///
/// # Examples
///
/// ```text
/// let ports = parse_alert_ports(alert.details.as_deref());
/// ```
fn parse_alert_ports(details: Option<&str>) -> Option<Vec<u16>> {
    let value = serde_json::from_str::<serde_json::Value>(details?).ok()?;
    value
        .get("ports")?
        .as_array()?
        .iter()
        .map(|item| {
            item.as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .or_else(|| item.as_str()?.parse().ok())
        })
        .collect()
}

/// Keeps summary examples short and readable, retaining at most 5 items.
///
/// # Arguments
/// - `values`: examples already collected
/// - `value`: example to append
///
/// # Returns
/// none
///
/// # Examples
///
/// ```text
/// push_example(&mut examples, "10.0.0.1:80".to_string());
/// ```
fn push_example(values: &mut Vec<String>, value: String) {
    if values.len() < 5 {
        values.push(value);
    }
}

/// Renders a count map as Markdown-friendly text.
///
/// # Arguments
/// - `values`: ordered name-to-count map
///
/// # Returns
/// Comma-separated `name=count` text; an empty map returns the empty-table placeholder
///
/// # Examples
///
/// ```text
/// let text = render_counts(&summary.vulnerability_types);
/// ```
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

/// Renders focus items as easy-to-scan subsection tables.
///
/// # Arguments
/// - `summary`: already aggregated report summary
///
/// # Returns
/// Markdown made by concatenating several `###` subsections
///
/// # Examples
///
/// ```text
/// let focus = render_focus_table(&summary);
/// ```
fn render_focus_table(summary: &ReportSummary) -> String {
    let sections = [
        ("新增开放端口", &summary.new_open_port_examples),
        ("非基准开放端口", &summary.non_baseline_open_port_examples),
        ("当前非基准 URL", &summary.non_baseline_url_examples),
        ("域名解析变化", &summary.dns_change_examples),
        ("漏洞", &summary.vulnerability_examples),
    ];
    let mut output = String::new();
    for (index, (title, examples)) in sections.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        output.push_str(&render_focus_section(title, examples));
    }
    output
}

/// Renders one focus category as a Markdown heading with an HTML table.
///
/// # Arguments
/// - `title`: subsection title
/// - `examples`: examples in this category
///
/// # Returns
/// Markdown with a `### title` heading plus a table
///
/// # Examples
///
/// ```text
/// let section = render_focus_section("Vulnerabilities", &examples);
/// ```
fn render_focus_section(title: &str, examples: &[String]) -> String {
    format!(
        "### {}\n\n{}",
        title,
        render_focus_html_table("重点信息", examples)
    )
}

/// Renders focus rows as an HTML table that Markdown viewers can accept.
///
/// # Arguments
/// - `header`: table-header text
/// - `values`: cell contents; an empty list shows the empty-table placeholder
///
/// # Returns
/// An HTML `<table>` fragment
///
/// # Examples
///
/// ```text
/// let table = render_focus_html_table("Focus", &values);
/// ```
fn render_focus_html_table(header: &str, values: &[String]) -> String {
    let rows = if values.is_empty() {
        vec!["无".to_string()]
    } else {
        values.to_vec()
    };
    let mut output = format!(
        "<table>\n<thead><tr><th>{}</th></tr></thead>\n<tbody>\n",
        html_escape(header)
    );
    for value in rows {
        output.push_str(&format!("<tr><td>{}</td></tr>\n", html_escape(&value)));
    }
    output.push_str("</tbody>\n</table>");
    output
}

/// Escapes text used in HTML table cells.
///
/// # Arguments
/// - `value`: raw text
///
/// # Returns
/// Escaped HTML text
///
/// # Examples
///
/// ```text
/// let safe = html_escape("poc<&>");
/// ```
fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            '\n' => escaped.push_str("<br>"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Describes the detail files included in the report package.
///
/// # Arguments
/// - `format`: configured detail output format
///
/// # Returns
/// Detail-file description written into `summary.md`
///
/// # Examples
///
/// ```text
/// let description = detail_file_description(ReportFormat::Xlsx);
/// ```
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn describes_configured_detail_files() {
        assert!(detail_file_description(ReportFormat::Xlsx).contains("details.xlsx"));
        assert!(detail_file_description(ReportFormat::Json).contains("details.json"));
        assert!(detail_file_description(ReportFormat::Csv).contains("alerts.csv"));
    }

    #[test]
    fn renders_focus_items_as_subsection_tables() {
        let summary = ReportSummary {
            new_open_port_examples: vec!["VPN系统 202.111.55.2:442".to_string()],
            non_baseline_open_port_examples: vec!["VPN系统 221.228.43.70:4433".to_string()],
            non_baseline_url_examples: vec!["VPN系统 http://vpn.telecomjs.com:4433/".to_string()],
            dns_change_examples: vec![],
            vulnerability_examples: vec!["http://example.test/ [high] poc<&>".to_string()],
            ..ReportSummary::default()
        };

        let rendered = render_focus_table(&summary);

        assert!(rendered.contains("### 新增开放端口"));
        assert!(rendered.contains("### 非基准开放端口"));
        assert!(rendered.contains("### 当前非基准 URL"));
        assert!(rendered.contains("### 域名解析变化"));
        assert!(rendered.contains("### 漏洞"));
        assert!(rendered.contains("<table>"));
        assert!(rendered.contains("VPN系统 http://vpn.telecomjs.com:4433/"));
        assert!(rendered.contains("<td>无</td>"));
        assert!(rendered.contains("poc&lt;&amp;&gt;"));
        assert!(!rendered.contains("| 分类 | 重点信息 |"));
    }

    #[test]
    fn counts_ports_inside_aggregated_alerts() {
        let alert = Alert {
            id: "a1".to_string(),
            batch_id: "b1".to_string(),
            system_id: None,
            system_name: None,
            kind: "port_change".to_string(),
            severity: "high".to_string(),
            subject: "10.0.0.1".to_string(),
            old_value: Some("closed/unknown".to_string()),
            new_value: Some("open".to_string()),
            details: Some(r#"{"count":2,"ports":[80,443]}"#.to_string()),
            created_at: Utc::now(),
        };

        assert_eq!(alert_port_count(&alert), 2);
        assert_eq!(
            alert_port_examples(&alert),
            vec!["10.0.0.1:80".to_string(), "10.0.0.1:443".to_string()]
        );

        let summary = ReportSummary::from_details(&[alert], &[], &[], &[]);
        assert_eq!(summary.new_open_ports, 2);
        assert_eq!(summary.new_open_port_examples[0], "10.0.0.1:80");
    }
}
