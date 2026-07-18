//! Interactive terminal dashboard for current watcher operational state.

use std::{
    io::{self, IsTerminal},
    time::{Duration, Instant},
};

use anyhow::Context;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table},
};

use crate::{
    db::Database,
    local_time,
    models::{DashboardSnapshot, DashboardStage},
};

const ACCENT: Color = Color::Cyan;
const PANEL: Color = Color::Rgb(31, 41, 55);
const MUTED: Color = Color::DarkGray;

/// Runs the interactive dashboard until the operator presses `q` or `Esc`.
///
/// # Errors
///
/// Returns an error when the standard output is not an interactive terminal or
/// when the terminal backend/database cannot be initialized.
pub fn run(db: &Database, refresh_interval: Duration) -> anyhow::Result<()> {
    anyhow::ensure!(
        io::stdout().is_terminal(),
        "dashboard requires an interactive terminal"
    );

    enable_raw_mode().context("failed to enable terminal raw mode")?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(error).context("failed to enter dashboard screen");
    }
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = match Terminal::new(backend) {
        Ok(terminal) => terminal,
        Err(error) => {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            return Err(error).context("failed to initialize dashboard terminal");
        }
    };

    let result = run_loop(
        &mut terminal,
        db,
        refresh_interval.max(Duration::from_millis(250)),
    );
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    db: &Database,
    refresh_interval: Duration,
) -> anyhow::Result<()> {
    let mut snapshot = db.dashboard_snapshot()?;
    let mut refreshed_at = Instant::now();
    loop {
        terminal.draw(|frame| render(frame, &snapshot, refresh_interval))?;
        let wait = refresh_interval.saturating_sub(refreshed_at.elapsed());
        if event::poll(wait)?
            && let Event::Key(key) = event::read()?
            && matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
        {
            return Ok(());
        }
        if refreshed_at.elapsed() >= refresh_interval {
            snapshot = db.dashboard_snapshot()?;
            refreshed_at = Instant::now();
        }
    }
}

fn render(frame: &mut Frame, snapshot: &DashboardSnapshot, refresh_interval: Duration) {
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

fn severity_style(severity: &str) -> Style {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => Style::default().fg(Color::Red),
        "high" => Style::default().fg(Color::LightRed),
        "medium" => Style::default().fg(Color::Yellow),
        "low" => Style::default().fg(Color::Green),
        _ => Style::default().fg(MUTED),
    }
}

fn status_style(status: &str) -> Style {
    match status.to_ascii_lowercase().as_str() {
        "running" => Style::default().fg(ACCENT),
        "completed" => Style::default().fg(Color::Green),
        "warning" | "interrupted" => Style::default().fg(Color::Yellow),
        "failed" => Style::default().fg(Color::Red),
        _ => Style::default().fg(MUTED),
    }
}

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

fn short_id(value: &str) -> String {
    value.chars().take(8).collect()
}

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
