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

/// Runs the interactive dashboard until the operator presses `q` or `Esc`.
///
/// # Arguments
///
/// - `db`: database handle for read-only queries.
/// - `refresh_interval`: snapshot refresh interval; never below 250ms.
///
/// # Returns
///
/// `Ok(())` when the operator exits on purpose.
///
/// # Errors
///
/// Returns an error if stdout is not an interactive terminal, or the terminal
/// backend / database cannot be initialized.
///
/// # Examples
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

/// Draws the dashboard in a loop and handles quit keys.
///
/// # Arguments
///
/// - `terminal`: ratatui terminal backend.
/// - `db`: database handle used to refresh the snapshot.
/// - `refresh_interval`: snapshot refresh interval.
///
/// # Returns
///
/// `Ok(())` after the user presses `q` / `Esc`.
///
/// # Errors
///
/// Returns an error if drawing, reading keys, or querying the snapshot fails.
///
/// # Examples
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
