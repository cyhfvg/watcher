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
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::db::Database;

mod render;

/// 运行交互式仪表盘, 直到操作员按下 `q` 或 `Esc`.
///
/// # 参数
///
/// - `db`: 只读查询用的数据库句柄.
/// - `refresh_interval`: 快照刷新间隔; 实际间隔不会低于 250ms.
///
/// # 返回
///
/// 操作员主动退出时返回 `Ok(())`.
///
/// # Errors
///
/// 标准输出不是交互终端, 或终端后端 / 数据库无法初始化时返回错误.
///
/// # 示例
///
/// ```no_run
/// # use std::time::Duration;
/// # use watcher::{dashboard, db::Database};
/// # fn demo(db: &Database) -> anyhow::Result<()> {
/// dashboard::run(db, Duration::from_secs(2))?;
/// # Ok(())
/// # }
/// ```
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

/// 在已初始化的终端中循环绘制仪表盘并响应退出按键.
///
/// # 参数
///
/// - `terminal`: ratatui 终端后端.
/// - `db`: 数据库句柄, 用于刷新快照.
/// - `refresh_interval`: 快照刷新间隔.
///
/// # 返回
///
/// 用户按 `q` / `Esc` 后返回 `Ok(())`.
///
/// # Errors
///
/// 绘制终端, 读取按键或查询快照失败时返回错误.
///
/// # 示例
///
/// ```text
/// run_loop(&mut terminal, db, refresh_interval)?;
/// ```
fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    db: &Database,
    refresh_interval: Duration,
) -> anyhow::Result<()> {
    let mut snapshot = db.dashboard_snapshot()?;
    let mut refreshed_at = Instant::now();
    loop {
        terminal.draw(|frame| render::render(frame, &snapshot, refresh_interval))?;
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
