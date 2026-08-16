//! Lightweight background process launcher and PID-file lifecycle for watcher daemon.

use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use anyhow::Context;

use crate::cli::{Commands, DaemonCommands};

/// Environment flag used to prevent a background child from spawning again.
const CHILD_ENV: &str = "WATCHER_DAEMON_CHILD";

/// Daemon status derived from the PID file and process table.
#[derive(Debug, Clone)]
pub enum DaemonStatus {
    /// No PID file exists.
    NotRunning,
    /// PID file exists and points to a watcher daemon process.
    Running { pid: u32 },
    /// PID file exists but is stale or unsafe to use.
    Stale { pid: u32, reason: String },
}

/// Returns whether the current subcommand should start as a background daemon.
///
/// True only for `daemon run` without `--once` / `--foreground`, and only when
/// this process is not already the daemon child.
///
/// # Arguments
///
/// - `command`: parsed CLI subcommand.
///
/// # Returns
///
/// `true` when a background child should be spawned first.
///
/// # Examples
///
/// ```no_run
/// # use watcher::{cli::Commands, daemon};
/// # fn demo(command: &Commands) {
/// if daemon::should_background(command) {
///     // spawn_background(...)
/// }
/// # }
/// ```
pub fn should_background(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Daemon(DaemonCommands::Run {
            once: false,
            foreground: false,
        })
    ) && env::var_os(CHILD_ENV).is_none()
}

/// Spawns the current executable in the background, writes the PID file, and
/// returns the child PID.
///
/// The child inherits the current command-line arguments and uses an
/// environment variable to avoid spawning itself again.
///
/// # Arguments
///
/// - `pid_path`: daemon PID file path.
///
/// # Returns
///
/// PID of the new background process.
///
/// # Errors
///
/// Returns an error if the PID file already points at a running daemon,
/// stale-PID cleanup fails, or spawning / writing the PID file fails.
///
/// # Examples
///
/// ```no_run
/// # use std::path::Path;
/// # use watcher::daemon;
/// # fn demo(pid_path: &Path) -> anyhow::Result<()> {
/// let pid = daemon::spawn_background(pid_path)?;
/// println!("started pid={pid}");
/// # Ok(())
/// # }
/// ```
pub fn spawn_background(pid_path: &Path) -> anyhow::Result<u32> {
    cleanup_stale_pid(pid_path)?;
    if let DaemonStatus::Running { pid } = status(pid_path)? {
        anyhow::bail!("watcher daemon is already running, pid={pid}");
    }

    let child = spawn_with_args(env::args_os().skip(1), true)
        .context("failed to spawn background daemon")?;
    write_pid(pid_path, child)?;
    Ok(child)
}

/// Starts a background daemon with explicit CLI arguments.
///
/// # Arguments
///
/// - `pid_path`: daemon PID file path.
/// - `args`: arguments passed to the child, typically `["daemon", "run"]`.
///
/// # Returns
///
/// PID of the new background process.
///
/// # Errors
///
/// Returns an error if a daemon is already running, or if spawn / PID write
/// fails.
///
/// # Examples
///
/// ```no_run
/// # use std::path::Path;
/// # use watcher::daemon;
/// # fn demo(pid_path: &Path) -> anyhow::Result<()> {
/// let pid = daemon::spawn_background_args(pid_path, ["daemon", "run"])?;
/// println!("restarted pid={pid}");
/// # Ok(())
/// # }
/// ```
pub fn spawn_background_args<I, S>(pid_path: &Path, args: I) -> anyhow::Result<u32>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    cleanup_stale_pid(pid_path)?;
    if let DaemonStatus::Running { pid } = status(pid_path)? {
        anyhow::bail!("watcher daemon is already running, pid={pid}");
    }
    let child = spawn_with_args(args, true).context("failed to spawn background daemon")?;
    write_pid(pid_path, child)?;
    Ok(child)
}

/// Reads and validates the daemon PID file.
///
/// # Arguments
///
/// - `pid_path`: PID file path.
///
/// # Returns
///
/// [`DaemonStatus`]: not running, running, or stale / unsafe.
///
/// # Errors
///
/// Returns an error if the PID file cannot be read or does not contain a
/// valid PID.
///
/// # Examples
///
/// ```no_run
/// # use std::path::Path;
/// # use watcher::daemon;
/// # fn demo(pid_path: &Path) -> anyhow::Result<()> {
/// match daemon::status(pid_path)? {
///     daemon::DaemonStatus::Running { pid } => println!("running {pid}"),
///     _ => println!("not running"),
/// }
/// # Ok(())
/// # }
/// ```
pub fn status(pid_path: &Path) -> anyhow::Result<DaemonStatus> {
    let Some(pid) = read_pid(pid_path)? else {
        return Ok(DaemonStatus::NotRunning);
    };
    if !process_alive(pid) {
        return Ok(DaemonStatus::Stale {
            pid,
            reason: "process is not running".to_string(),
        });
    }
    if !looks_like_watcher_daemon(pid) {
        return Ok(DaemonStatus::Stale {
            pid,
            reason: "pid belongs to a different process".to_string(),
        });
    }
    Ok(DaemonStatus::Running { pid })
}

/// Sends SIGTERM to a running daemon and waits for it to exit.
///
/// # Arguments
///
/// - `pid_path`: PID file path.
///
/// # Returns
///
/// [`DaemonStatus::NotRunning`] when the process stopped; `Stale` after a
/// stale PID is removed; `Running` if it is still alive after the timeout.
///
/// # Errors
///
/// Returns an error if status lookup, signal delivery, or PID file removal
/// fails.
///
/// # Examples
///
/// ```no_run
/// # use std::path::Path;
/// # use watcher::daemon;
/// # fn demo(pid_path: &Path) -> anyhow::Result<()> {
/// let _ = daemon::stop(pid_path)?;
/// # Ok(())
/// # }
/// ```
pub fn stop(pid_path: &Path) -> anyhow::Result<DaemonStatus> {
    match status(pid_path)? {
        DaemonStatus::NotRunning => Ok(DaemonStatus::NotRunning),
        DaemonStatus::Stale { pid, reason } => {
            remove_pid_file(pid_path)?;
            Ok(DaemonStatus::Stale { pid, reason })
        }
        DaemonStatus::Running { pid } => {
            terminate(pid)?;
            for _ in 0..40 {
                if !process_alive(pid) {
                    remove_pid_file(pid_path)?;
                    return Ok(DaemonStatus::NotRunning);
                }
                thread::sleep(Duration::from_millis(250));
            }
            Ok(DaemonStatus::Running { pid })
        }
    }
}

/// Removes a stale PID file when it is safe to do so.
///
/// # Arguments
///
/// - `pid_path`: PID file path.
///
/// # Returns
///
/// `Ok(())` when no cleanup is needed or cleanup succeeds.
///
/// # Errors
///
/// Returns an error if status lookup or file removal fails.
///
/// # Examples
///
/// ```no_run
/// # use std::path::Path;
/// # use watcher::daemon;
/// # fn demo(pid_path: &Path) -> anyhow::Result<()> {
/// daemon::cleanup_stale_pid(pid_path)?;
/// # Ok(())
/// # }
/// ```
pub fn cleanup_stale_pid(pid_path: &Path) -> anyhow::Result<()> {
    if matches!(status(pid_path)?, DaemonStatus::Stale { .. }) {
        remove_pid_file(pid_path)?;
    }
    Ok(())
}

/// Returns whether the current process is the daemon child.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// `true` when the `WATCHER_DAEMON_CHILD` environment variable is set.
///
/// # Examples
///
/// ```
/// let _ = watcher::daemon::is_daemon_child();
/// ```
pub fn is_daemon_child() -> bool {
    env::var_os(CHILD_ENV).is_some()
}

/// Writes the current process PID to the PID file.
///
/// # Arguments
///
/// - `pid_path`: PID file path.
///
/// # Returns
///
/// `Ok(())` when the write succeeds.
///
/// # Errors
///
/// Returns an error if the parent directory cannot be created or the file
/// cannot be written.
///
/// # Examples
///
/// ```no_run
/// # use std::path::Path;
/// # use watcher::daemon;
/// # fn demo(pid_path: &Path) -> anyhow::Result<()> {
/// daemon::write_current_pid(pid_path)?;
/// # Ok(())
/// # }
/// ```
pub fn write_current_pid(pid_path: &Path) -> anyhow::Result<()> {
    write_pid(pid_path, std::process::id())
}

/// Deletes the PID file; a missing file is treated as success.
///
/// # Arguments
///
/// - `pid_path`: PID file path.
///
/// # Returns
///
/// `Ok(())` when the file is removed or does not exist.
///
/// # Errors
///
/// Returns an error on any IO failure other than `NotFound`.
///
/// # Examples
///
/// ```no_run
/// # use std::path::Path;
/// # use watcher::daemon;
/// # fn demo(pid_path: &Path) -> anyhow::Result<()> {
/// daemon::remove_pid_file(pid_path)?;
/// # Ok(())
/// # }
/// ```
pub fn remove_pid_file(pid_path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(pid_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove {}", pid_path.display()))
        }
    }
}

/// Starts the current executable with the given arguments.
///
/// # Arguments
///
/// - `args`: arguments passed to the child.
/// - `background`: when `true`, detaches stdio and sets the daemon-child
///   environment variable.
///
/// # Returns
///
/// Child process PID.
///
/// # Errors
///
/// Returns an error if the current executable path cannot be resolved,
/// `/dev/null` cannot be opened, or `spawn` fails.
///
/// # Examples
///
/// ```text
/// let pid = spawn_with_args(["daemon", "run"], true)?;
/// ```
fn spawn_with_args<I, S>(args: I, background: bool) -> anyhow::Result<u32>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let executable = env::current_exe()?;
    let mut command = Command::new(executable);
    command.args(args.into_iter().map(Into::into));
    if background {
        let null = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")?;
        command
            .env(CHILD_ENV, "1")
            .stdin(Stdio::from(null.try_clone()?))
            .stdout(Stdio::from(null.try_clone()?))
            .stderr(Stdio::from(null));
    }
    Ok(command.spawn()?.id())
}

/// Writes a PID to the file, creating parent directories if needed.
///
/// # Arguments
///
/// - `pid_path`: PID file path.
/// - `pid`: process id to record.
///
/// # Returns
///
/// `Ok(())` when the write succeeds.
///
/// # Errors
///
/// Returns an error if directory creation or file write fails.
///
/// # Examples
///
/// ```text
/// write_pid(pid_path, child)?;
/// ```
fn write_pid(pid_path: &Path, pid: u32) -> anyhow::Result<()> {
    if let Some(parent) = pid_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(pid_path, format!("{pid}\n"))
        .with_context(|| format!("failed to write {}", pid_path.display()))?;
    Ok(())
}

/// Reads the process id stored in the PID file.
///
/// # Arguments
///
/// - `pid_path`: PID file path.
///
/// # Returns
///
/// `None` when the file is missing; otherwise the parsed PID.
///
/// # Errors
///
/// Returns an error if the file cannot be read or does not contain a valid
/// `u32`.
///
/// # Examples
///
/// ```text
/// let Some(pid) = read_pid(pid_path)? else { return Ok(DaemonStatus::NotRunning); };
/// ```
fn read_pid(pid_path: &Path) -> anyhow::Result<Option<u32>> {
    let content = match fs::read_to_string(pid_path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", pid_path.display()));
        }
    };
    let pid = content
        .trim()
        .parse::<u32>()
        .with_context(|| format!("invalid pid file {}", pid_path.display()))?;
    Ok(Some(pid))
}

/// Probes whether a process still exists with `kill -0`.
///
/// # Arguments
///
/// - `pid`: process id to probe.
///
/// # Returns
///
/// `true` if the process exists; a failed `kill` is treated as not running.
///
/// # Examples
///
/// ```text
/// if process_alive(pid) { /* still running */ }
/// ```
fn process_alive(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Sends SIGTERM to a process.
///
/// # Arguments
///
/// - `pid`: target process id.
///
/// # Returns
///
/// `Ok(())` when the signal is delivered.
///
/// # Errors
///
/// Returns an error if `kill` cannot be started or exits non-zero.
///
/// # Examples
///
/// ```text
/// terminate(pid)?;
/// ```
fn terminate(pid: u32) -> anyhow::Result<()> {
    let status = Command::new("kill").arg(pid.to_string()).status()?;
    anyhow::ensure!(status.success(), "failed to send SIGTERM to pid {pid}");
    Ok(())
}

/// Checks whether a PID still points at a watcher daemon.
///
/// Reads `/proc/{pid}/cmdline` and requires `watcher`, `daemon`, and `run`.
/// If the cmdline cannot be read, returns `true` conservatively so another
/// process's PID is not deleted by mistake.
///
/// # Arguments
///
/// - `pid`: process id to validate.
///
/// # Returns
///
/// `true` when the process looks like a watcher daemon, or when cmdline
/// cannot be read.
///
/// # Examples
///
/// ```text
/// if !looks_like_watcher_daemon(pid) { /* treat as stale */ }
/// ```
fn looks_like_watcher_daemon(pid: u32) -> bool {
    let path = format!("/proc/{pid}/cmdline");
    let Ok(bytes) = fs::read(path) else {
        return true;
    };
    let command = String::from_utf8_lossy(&bytes).replace('\0', " ");
    command.contains("watcher") && command.contains("daemon") && command.contains("run")
}
