//! 仪表盘画面绘制与样式辅助.

use std::time::Duration;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table},
};

use crate::{
    local_time,
    models::{DashboardSnapshot, DashboardStage},
};

const ACCENT: Color = Color::Cyan;
const PANEL: Color = Color::Rgb(31, 41, 55);
const MUTED: Color = Color::DarkGray;

/// 绘制完整仪表盘画面, 包括页头, 指标, 进度, 告警和页脚.
///
/// # 参数
///
/// - `frame`: 当前帧画布.
/// - `snapshot`: 最新运营快照.
/// - `refresh_interval`: 页脚展示的自动刷新间隔.
///
/// # 返回
///
/// 无.
///
/// # 示例
///
/// ```text
/// render(frame, &snapshot, Duration::from_secs(2));
/// ```
pub(super) fn render(frame: &mut Frame, snapshot: &DashboardSnapshot, refresh_interval: Duration) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Length(12),
            Constraint::Min(7),
            Constraint::Length(2),
        ])
        .split(frame.area());

    render_header(frame, areas[0], snapshot);
    render_metrics(frame, areas[1], snapshot);
    render_progress(frame, areas[2], snapshot);
    render_alerts(frame, areas[3], snapshot);
    frame.render_widget(
        Paragraph::new(format!(
            " q / Esc 退出   ·   自动刷新 {}s   ·   数据时间 {}",
            refresh_interval.as_secs().max(1),
            local_time::rfc3339_to_local(&snapshot.generated_at)
        ))
        .style(Style::default().fg(MUTED)),
        areas[4],
    );
}

/// 绘制顶部运行总览, 显示当前批次短编号和状态.
///
/// # 参数
///
/// - `frame`: 当前帧画布.
/// - `area`: 页头区域.
/// - `snapshot`: 最新运营快照.
///
/// # 返回
///
/// 无.
///
/// # 示例
///
/// ```text
/// render_header(frame, area, snapshot);
/// ```
fn render_header(frame: &mut Frame, area: Rect, snapshot: &DashboardSnapshot) {
    let (batch_label, status) = snapshot
        .latest_batch
        .as_ref()
        .map(|batch| (short_id(&batch.id), batch.status.as_str()))
        .unwrap_or_else(|| ("暂无批次".to_string(), "idle"));
    let title = Line::from(vec![
        Span::styled(
            " WATCHER ",
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "  OPERATIONS DASHBOARD",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("     "),
        Span::styled(format!("批次 {batch_label}"), Style::default().fg(MUTED)),
        Span::raw("  "),
        Span::styled(
            status.to_ascii_uppercase(),
            status_style(status).add_modifier(Modifier::BOLD),
        ),
    ]);
    frame.render_widget(Paragraph::new(title).block(panel_block("运行总览")), area);
}

/// 绘制资产, 暴露面, 数据量和基准四张指标卡片.
///
/// # 参数
///
/// - `frame`: 当前帧画布.
/// - `area`: 指标区域.
/// - `snapshot`: 最新运营快照.
///
/// # 返回
///
/// 无.
///
/// # 示例
///
/// ```text
/// render_metrics(frame, area, snapshot);
/// ```
fn render_metrics(frame: &mut Frame, area: Rect, snapshot: &DashboardSnapshot) {
    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25); 4])
        .split(area);
    let assets = &snapshot.assets;
    metric_card(
        frame,
        cards[0],
        "资产",
        format!(
            "{} 系统 · {} 域名 · {} IP",
            assets.systems, assets.domains, assets.ips
        ),
        ACCENT,
    );
    metric_card(
        frame,
        cards[1],
        "暴露面",
        format!(
            "{} 开放端口 · {} Web",
            assets.open_ports, assets.web_services
        ),
        Color::Yellow,
    );
    metric_card(
        frame,
        cards[2],
        "数据量",
        format!("{} URL · {} 字典", assets.urls, assets.dictionary_paths),
        Color::Green,
    );
    metric_card(
        frame,
        cards[3],
        "基准",
        format!("{} 资产 · {} 端口", assets.baseline_assets, assets.ports),
        Color::Magenta,
    );
}

/// 绘制单张指标卡片, 标题只出现在边框上.
///
/// # 参数
///
/// - `frame`: 当前帧画布.
/// - `area`: 卡片区域.
/// - `title`: 边框标题.
/// - `value`: 卡片正文.
/// - `color`: 正文强调色.
///
/// # 返回
///
/// 无.
///
/// # 示例
///
/// ```text
/// metric_card(frame, area, "资产", value, ACCENT);
/// ```
fn metric_card(frame: &mut Frame, area: Rect, title: &str, value: String, color: Color) {
    frame.render_widget(
        Paragraph::new(Line::styled(
            value,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
        .block(panel_block(title)),
        area,
    );
}

/// 绘制阶段列表, 完成度条以及风险 / 补偿队列摘要.
///
/// # 参数
///
/// - `frame`: 当前帧画布.
/// - `area`: 进度区域.
/// - `snapshot`: 最新运营快照.
///
/// # 返回
///
/// 无.
///
/// # 示例
///
/// ```text
/// render_progress(frame, area, snapshot);
/// ```
fn render_progress(frame: &mut Frame, area: Rect, snapshot: &DashboardSnapshot) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(54), Constraint::Percentage(46)])
        .split(area);
    let completed = snapshot
        .stages
        .iter()
        .filter(|stage| stage.status == "completed" || stage.status == "warning")
        .count();
    let percent = if snapshot.stages.is_empty() {
        0
    } else {
        (completed.saturating_mul(100) / snapshot.stages.len()) as u16
    };
    let mut stage_items: Vec<ListItem> = snapshot.stages.iter().map(stage_item).collect();
    if stage_items.is_empty() {
        stage_items.push(ListItem::new(Line::styled(
            "尚未开始监测任务",
            Style::default().fg(MUTED),
        )));
    }
    frame.render_widget(
        List::new(stage_items).block(panel_block("任务进度 / STAGES")),
        columns[0],
    );

    let severity = &snapshot.alert_severity;
    let batch_text = snapshot.latest_batch.as_ref().map_or_else(
        || "没有历史批次".to_string(),
        |batch| format!("告警 {}  ·  漏洞 {}", batch.alerts, batch.vulnerabilities),
    );
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(7)])
        .split(columns[1]);
    frame.render_widget(
        Gauge::default()
            .block(panel_block("当前批次完成度"))
            .gauge_style(Style::default().fg(ACCENT).bg(PANEL))
            .label(format!("{completed}/{} 阶段", snapshot.stages.len()))
            .percent(percent),
        right[0],
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                batch_text,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Line::from(vec![
                Span::styled(
                    format!("CRIT {}  ", severity.critical),
                    severity_style("critical"),
                ),
                Span::styled(format!("HIGH {}  ", severity.high), severity_style("high")),
                Span::styled(
                    format!("MED {}  ", severity.medium),
                    severity_style("medium"),
                ),
                Span::styled(format!("LOW {}", severity.low), severity_style("low")),
            ]),
            Line::styled(
                format!(
                    "队列  pending {} · running {} · done {}",
                    snapshot.queue.pending, snapshot.queue.running, snapshot.queue.done
                ),
                Style::default().fg(MUTED),
            ),
        ])
        .block(panel_block("风险与补偿队列")),
        right[1],
    );
}

/// 把单个流水线阶段格式化为列表项.
///
/// # 参数
///
/// - `stage`: 批次阶段状态.
///
/// # 返回
///
/// 带中文阶段名, 状态和截断详情的列表项.
///
/// # 示例
///
/// ```text
/// let item = stage_item(stage);
/// ```
fn stage_item(stage: &DashboardStage) -> ListItem<'static> {
    let detail = stage
        .detail
        .as_deref()
        .map(|detail| format!(" · {}", truncate(detail, 36)))
        .unwrap_or_default();
    ListItem::new(Line::from(vec![
        Span::styled(
            format!(" {:<21}", stage_label(&stage.stage)),
            Style::default().fg(Color::White),
        ),
        Span::styled(
            format!("{:<10}", stage.status.to_ascii_uppercase()),
            status_style(&stage.status).add_modifier(Modifier::BOLD),
        ),
        Span::styled(detail, Style::default().fg(MUTED)),
    ]))
}

/// 绘制最近告警表格.
///
/// # 参数
///
/// - `frame`: 当前帧画布.
/// - `area`: 告警表格区域.
/// - `snapshot`: 最新运营快照.
///
/// # 返回
///
/// 无.
///
/// # 示例
///
/// ```text
/// render_alerts(frame, area, snapshot);
/// ```
fn render_alerts(frame: &mut Frame, area: Rect, snapshot: &DashboardSnapshot) {
    let rows: Vec<Row> = snapshot
        .recent_alerts
        .iter()
        .map(|alert| {
            Row::new(vec![
                Cell::from(alert.severity.to_ascii_uppercase())
                    .style(severity_style(&alert.severity).add_modifier(Modifier::BOLD)),
                Cell::from(alert.kind.as_str()),
                Cell::from(alert.system_name.as_deref().unwrap_or("-")),
                Cell::from(truncate(&alert.subject, 56)),
                Cell::from(local_time::rfc3339_to_local(&alert.created_at)),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(16),
            Constraint::Length(16),
            Constraint::Min(24),
            Constraint::Length(21),
        ],
    )
    .header(
        Row::new(["级别", "类型", "系统", "对象", "时间"])
            .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
    )
    .block(panel_block("最近告警 / RECENT ALERTS"))
    .column_spacing(1);
    frame.render_widget(table, area);
}

/// 构造带圆角边框和强调色标题的面板.
///
/// # 参数
///
/// - `title`: 面板标题.
///
/// # 返回
///
/// 可复用的 `Block` 边框.
///
/// # 示例
///
/// ```text
/// let block = panel_block("运行总览");
/// ```
fn panel_block(title: &str) -> Block<'_> {
    Block::default()
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(PANEL))
}

/// 按告警级别返回对应前景色.
///
/// # 参数
///
/// - `severity`: 告警级别文本, 大小写不敏感.
///
/// # 返回
///
/// 用于表格和摘要的 `Style`.
///
/// # 示例
///
/// ```text
/// let style = severity_style("critical");
/// ```
fn severity_style(severity: &str) -> Style {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => Style::default().fg(Color::Red),
        "high" => Style::default().fg(Color::LightRed),
        "medium" => Style::default().fg(Color::Yellow),
        "low" => Style::default().fg(Color::Green),
        _ => Style::default().fg(MUTED),
    }
}

/// 按批次或阶段状态返回对应前景色.
///
/// # 参数
///
/// - `status`: 状态文本, 大小写不敏感.
///
/// # 返回
///
/// 用于页头和阶段列表的 `Style`.
///
/// # 示例
///
/// ```text
/// let style = status_style("running");
/// ```
fn status_style(status: &str) -> Style {
    match status.to_ascii_lowercase().as_str() {
        "running" => Style::default().fg(ACCENT),
        "completed" => Style::default().fg(Color::Green),
        "warning" | "interrupted" => Style::default().fg(Color::Yellow),
        "failed" => Style::default().fg(Color::Red),
        _ => Style::default().fg(MUTED),
    }
}

/// 把内部阶段标识映射为中文标签.
///
/// # 参数
///
/// - `stage`: 稳定阶段名, 例如 `dns` 或 `web_enum`.
///
/// # 返回
///
/// 中文阶段名; 未知阶段返回 `自定义阶段`.
///
/// # 示例
///
/// ```text
/// let label = stage_label("port_scan");
/// ```
fn stage_label(stage: &str) -> &'static str {
    match stage {
        "dns" => "DNS 解析",
        "port_scan" => "端口扫描",
        "fingerprint" => "服务指纹",
        "web_enum" => "Web 枚举",
        "vulnerability_scan" => "漏洞检查",
        "detailed_fingerprint" => "深度指纹",
        "report" => "报告打包",
        "email_notification" => "邮件通知",
        _ => "自定义阶段",
    }
}

/// 截取标识符前 8 个字符作为短编号.
///
/// # 参数
///
/// - `value`: 完整批次或对象 id.
///
/// # 返回
///
/// 最多 8 个字符的前缀.
///
/// # 示例
///
/// ```text
/// let label = short_id(&batch.id);
/// ```
fn short_id(value: &str) -> String {
    value.chars().take(8).collect()
}

/// 按字符数截断文本, 超长时追加省略号.
///
/// # 参数
///
/// - `value`: 原始文本.
/// - `maximum`: 保留的最大字符数, 不含省略号.
///
/// # 返回
///
/// 截断后的展示字符串.
///
/// # 示例
///
/// ```text
/// let text = truncate(subject, 56);
/// ```
fn truncate(value: &str, maximum: usize) -> String {
    let mut chars = value.chars();
    let prefix: String = chars.by_ref().take(maximum).collect();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;

    #[test]
    fn maps_importance_levels_to_distinct_colors() {
        assert_eq!(severity_style("critical").fg, Some(Color::Red));
        assert_eq!(severity_style("high").fg, Some(Color::LightRed));
        assert_eq!(severity_style("medium").fg, Some(Color::Yellow));
        assert_eq!(severity_style("low").fg, Some(Color::Green));
    }

    #[test]
    fn renders_core_dashboard_sections() {
        let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
        terminal
            .draw(|frame| render(frame, &DashboardSnapshot::default(), Duration::from_secs(2)))
            .unwrap();
        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(content.contains("WATCHER"));
        assert!(content.contains("STAGES"));
        assert!(content.contains("RECENT ALERTS"));
    }

    #[test]
    fn renders_metric_title_only_in_its_border() {
        let mut terminal = Terminal::new(TestBackend::new(40, 5)).unwrap();
        terminal
            .draw(|frame| metric_card(frame, frame.area(), "唯一指标", "42".to_string(), ACCENT))
            .unwrap();
        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        let content_without_padding = content.replace(' ', "");

        assert_eq!(content_without_padding.matches("唯一指标").count(), 1);
    }
}
