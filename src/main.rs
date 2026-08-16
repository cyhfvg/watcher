//! Command-line entry point for watcher.

use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use watcher::{
    cli::{self, Cli, Commands, DaemonCommands, DictCommands, TaskCommands},
    config::AppConfig,
    daemon, dashboard,
    db::Database,
    dict, local_time, logging, monitor, report,
};

/// Parses the command line and dispatches to the matching watcher subcommand.
///
/// # Arguments
///
/// none. Arguments come from process `argv`.
///
/// # Returns
///
/// `Ok(())` when the subcommand completes successfully.
///
/// # Errors
///
/// Returns an error if configuration, database, or logging initialization
/// fails, or if the selected subcommand fails.
///
/// # Examples
///
/// ```text
/// cargo run -- daemon status
/// ```
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.example {
        print!("{}", AppConfig::example_yaml()?);
        return Ok(());
    }

    let command = cli.command.unwrap_or(Commands::Init);
    let config = AppConfig::load_or_create().context("failed to load watcher configuration")?;
    local_time::configure(&config.display.timezone)
        .context("failed to configure display timezone")?;
    let db = Database::open(&config.database.path).context("failed to open watcher database")?;
    db.migrate().context("failed to migrate watcher database")?;
    logging::init(&db).context("failed to initialize logging")?;
    tracing::info!(
        database = %config.database.path.display(),
        display_timezone = %local_time::configured_timezone(),
        "watcher command started"
    );
    let pid_path = config.daemon_pid_path();

    if daemon::should_background(&command) {
        let pid = daemon::spawn_background(&pid_path).context("failed to start watcher daemon")?;
        println!(
            "watcher daemon started in background, pid={}, pid_file={}",
            pid,
            pid_path.display()
        );
        return Ok(());
    }

    match command {
        Commands::Init => {
            println!("config: {}", config.config_path.display());
            println!("database: {}", config.database.path.display());
        }
        Commands::Baseline(command) => cli::handle_baseline(&db, command)?,
        Commands::System(command) => cli::handle_systems(&db, command)?,
        Commands::Daemon(DaemonCommands::Run { once, foreground }) => {
            if !once && (foreground || daemon::is_daemon_child()) {
                daemon::cleanup_stale_pid(&pid_path)?;
                daemon::write_current_pid(&pid_path)?;
            }
            let result = monitor::scheduler::run_daemon(db, config, once).await;
            if !once {
                let _ = daemon::remove_pid_file(&pid_path);
            }
            result?;
        }
        Commands::Daemon(DaemonCommands::Status) => {
            print_daemon_status(&pid_path)?;
        }
        Commands::Daemon(DaemonCommands::Stop) => {
            let before_stop = daemon::status(&pid_path)?;
            match daemon::stop(&pid_path)? {
                daemon::DaemonStatus::NotRunning => {
                    interrupt_batches_after_daemon_exit(&db, &before_stop)?;
                    println!("watcher daemon is not running");
                }
                daemon::DaemonStatus::Stale { pid, reason } => {
                    interrupt_batches_after_daemon_exit(&db, &before_stop)?;
                    println!("removed stale pid file: pid={pid}, reason={reason}");
                }
                daemon::DaemonStatus::Running { pid } => {
                    anyhow::bail!("failed to stop watcher daemon within timeout, pid={pid}");
                }
            }
        }
        Commands::Daemon(DaemonCommands::Restart { foreground }) => {
            let before_stop = daemon::status(&pid_path)?;
            match daemon::stop(&pid_path)? {
                daemon::DaemonStatus::Running { pid } => {
                    anyhow::bail!("failed to stop watcher daemon within timeout, pid={pid}");
                }
                daemon::DaemonStatus::Stale { pid, reason } => {
                    interrupt_batches_after_daemon_exit(&db, &before_stop)?;
                    println!("removed stale pid file: pid={pid}, reason={reason}");
                }
                daemon::DaemonStatus::NotRunning => {
                    interrupt_batches_after_daemon_exit(&db, &before_stop)?;
                }
            }
            if foreground {
                daemon::write_current_pid(&pid_path)?;
                let result = monitor::scheduler::run_daemon(db, config, false).await;
                let _ = daemon::remove_pid_file(&pid_path);
                result?;
            } else {
                let pid = daemon::spawn_background_args(&pid_path, ["daemon", "run"])
                    .context("failed to restart watcher daemon")?;
                println!(
                    "watcher daemon restarted in background, pid={}, pid_file={}",
                    pid,
                    pid_path.display()
                );
            }
        }
        Commands::Task(TaskCommands::Run { once }) => {
            if once {
                monitor::scheduler::run_single_batch(&db, &config).await?;
            } else {
                monitor::scheduler::run_daemon(db, config, false).await?;
            }
        }
        Commands::Task(TaskCommands::List) => cli::print_batches(&db)?,
        Commands::Task(TaskCommands::Status { batch }) => {
            cli::print_batch_status(&db, batch.as_deref())?
        }
        Commands::Task(TaskCommands::Stop { batch }) => {
            db.request_batch_stop(batch.as_deref())?;
            println!("stop requested");
        }
        Commands::Log(command) => cli::handle_logs(&db, command)?,
        Commands::Dict(DictCommands::Path(command)) => dict::paths::handle(&db, command)?,
        Commands::Url(command) => cli::handle_urls(&db, command)?,
        Commands::Port(command) => cli::handle_ports(&db, command)?,
        Commands::Ip(command) => cli::handle_ips(&db, command)?,
        Commands::Name(command) => cli::handle_names(&db, command)?,
        Commands::Report { batch } => {
            let package = report::build_report_package(&db, &config, batch.as_deref())?;
            println!("{}", package.zip_path.display());
        }
        Commands::Dashboard { refresh_seconds } => {
            dashboard::run(&db, Duration::from_secs(refresh_seconds.max(1)))?;
        }
    }

    Ok(())
}

/// After the daemon is confirmed stopped, marks still-running batches as
/// interrupted.
///
/// # Arguments
///
/// - `db`: database handle used to interrupt unfinished batches.
/// - `before_stop`: daemon status read before the stop was issued.
///
/// # Returns
///
/// `Ok(())` when no interrupt is needed or the interrupt succeeds.
///
/// # Errors
///
/// Returns an error if updating batch status fails.
///
/// # Examples
///
/// ```text
/// interrupt_batches_after_daemon_exit(&db, &before_stop)?;
/// ```
fn interrupt_batches_after_daemon_exit(
    db: &Database,
    before_stop: &daemon::DaemonStatus,
) -> anyhow::Result<()> {
    if matches!(
        before_stop,
        daemon::DaemonStatus::Running { .. } | daemon::DaemonStatus::Stale { .. }
    ) {
        db.interrupt_running_batches("watcher daemon stopped before finalizing batch")?;
    }
    Ok(())
}

/// Prints daemon status from the PID file.
///
/// # Arguments
///
/// - `pid_path`: daemon PID file path.
///
/// # Returns
///
/// `Ok(())` after the status has been printed to stdout.
///
/// # Errors
///
/// Returns an error if the PID file cannot be read or validated.
///
/// # Examples
///
/// ```text
/// print_daemon_status(&pid_path)?;
/// ```
fn print_daemon_status(pid_path: &std::path::Path) -> anyhow::Result<()> {
    match daemon::status(pid_path)? {
        daemon::DaemonStatus::NotRunning => {
            println!("status=stopped");
            println!("pid_file={}", pid_path.display());
        }
        daemon::DaemonStatus::Running { pid } => {
            println!("status=running");
            println!("pid={pid}");
            println!("pid_file={}", pid_path.display());
        }
        daemon::DaemonStatus::Stale { pid, reason } => {
            println!("status=stale");
            println!("pid={pid}");
            println!("reason={reason}");
            println!("pid_file={}", pid_path.display());
        }
    }
    Ok(())
}
