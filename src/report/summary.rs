//! 监控摘要 Markdown 渲染.

use std::collections::BTreeMap;

use crate::{
    config::ReportFormat,
    local_time,
    models::{Alert, PortAsset, UrlAsset, Vulnerability},
};

/// 渲染给人阅读的监控摘要 Markdown.
///
/// # 参数
/// - `status`: 批次执行状态
/// - `alerts`: 本批次告警
/// - `vulns`: 本批次漏洞
/// - `urls`: 当前 URL 资产
/// - `open_ports`: 当前开放端口
/// - `format`: 明细文件格式, 用于说明附件
///
/// # 返回
/// 完整的 `summary.md` 文本
///
/// # 示例
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

/// 由明细行汇总出的报告摘要.
#[derive(Debug, Default)]
struct ReportSummary {
    /// 报告时刻的 URL 资产总数.
    total_urls: usize,
    /// 属于导入基准的 URL 资产数.
    baseline_urls: usize,
    /// 基准之外发现的 URL 资产数.
    non_baseline_urls: usize,
    /// 报告时刻当前开放端口总数.
    total_open_ports: usize,
    /// 属于导入基准的开放端口数.
    baseline_open_ports: usize,
    /// 基准之外发现的开放端口数.
    non_baseline_open_ports: usize,
    /// 本批次新增开放端口告警数.
    new_open_ports: usize,
    /// 本批次关闭端口告警数.
    closed_ports: usize,
    /// DNS 解析变化条数.
    dns_changes: usize,
    /// 按 POC 标识分组的漏洞计数.
    vulnerability_types: BTreeMap<String, usize>,
    /// 新增开放端口的可读示例.
    new_open_port_examples: Vec<String>,
    /// 当前非基准开放端口的可读示例.
    non_baseline_open_port_examples: Vec<String>,
    /// 非基准 URL 的可读示例.
    non_baseline_url_examples: Vec<String>,
    /// DNS 变化的可读示例.
    dns_change_examples: Vec<String>,
    /// 漏洞发现的可读示例.
    vulnerability_examples: Vec<String>,
}

impl ReportSummary {
    /// 由告警, 漏洞与资产明细构建聚合摘要.
    ///
    /// # 参数
    /// - `alerts`: 本批次告警
    /// - `vulns`: 本批次漏洞
    /// - `urls`: 当前 URL 资产
    /// - `ports`: 当前开放端口
    ///
    /// # 返回
    /// 填充后的 [`ReportSummary`]
    ///
    /// # 示例
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

/// 统计 IP 级 `port_change` 告警中编码的端口数.
///
/// # 参数
/// - `alert`: 端口变化告警
///
/// # 返回
/// 解析到的端口数; 无法解析时返回 `1`
///
/// # 示例
///
/// ```text
/// let count = alert_port_count(&alert);
/// ```
fn alert_port_count(alert: &Alert) -> usize {
    parse_alert_ports(alert.details.as_deref())
        .map(|ports| ports.len().max(1))
        .unwrap_or(1)
}

/// 从聚合端口变化告警构建 `ip:port` 示例.
///
/// # 参数
/// - `alert`: 端口变化告警
///
/// # 返回
/// 可读的 `ip:port` 列表; 无法解析时回退为告警主题
///
/// # 示例
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

/// 从告警 details 解析 `{"count":N,"ports":[...]}`.
///
/// # 参数
/// - `details`: 告警 JSON 详情
///
/// # 返回
/// 解析成功时返回端口列表, 否则 `None`
///
/// # 示例
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

/// 保持摘要示例简短可读, 最多保留 5 条.
///
/// # 参数
/// - `values`: 已收集的示例
/// - `value`: 待追加的示例
///
/// # 返回
/// 无
///
/// # 示例
///
/// ```text
/// push_example(&mut examples, "10.0.0.1:80".to_string());
/// ```
fn push_example(values: &mut Vec<String>, value: String) {
    if values.len() < 5 {
        values.push(value);
    }
}

/// 将计数表渲染为适合 Markdown 的文本.
///
/// # 参数
/// - `values`: 名称到计数的有序映射
///
/// # 返回
/// `name=count` 逗号分隔文本; 空表返回 `"无"`
///
/// # 示例
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

/// 将重点项渲染为便于扫读的子节表格.
///
/// # 参数
/// - `summary`: 已聚合的报告摘要
///
/// # 返回
/// 多个 `###` 子节拼接后的 Markdown
///
/// # 示例
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

/// 将一个重点分类渲染为带 HTML 表的 Markdown 标题.
///
/// # 参数
/// - `title`: 子节标题
/// - `examples`: 该分类下的示例
///
/// # 返回
/// `### title` 加表格的 Markdown
///
/// # 示例
///
/// ```text
/// let section = render_focus_section("漏洞", &examples);
/// ```
fn render_focus_section(title: &str, examples: &[String]) -> String {
    format!(
        "### {}\n\n{}",
        title,
        render_focus_html_table("重点信息", examples)
    )
}

/// 将重点行渲染为 Markdown 查看器可接受的 HTML 表.
///
/// # 参数
/// - `header`: 表头文本
/// - `values`: 单元格内容; 空列表显示 `"无"`
///
/// # 返回
/// HTML `<table>` 片段
///
/// # 示例
///
/// ```text
/// let table = render_focus_html_table("重点信息", &values);
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

/// 转义 HTML 表格单元格中的文本.
///
/// # 参数
/// - `value`: 原始文本
///
/// # 返回
/// 转义后的 HTML 文本
///
/// # 示例
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

/// 描述报告包中包含的明细文件.
///
/// # 参数
/// - `format`: 配置的明细输出格式
///
/// # 返回
/// 写入 `summary.md` 的明细文件说明
///
/// # 示例
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
