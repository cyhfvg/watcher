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

/// Returns true when the current command should be launched in the background.
pub fn should_background(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Daemon(DaemonCommands::Run {
            once: false,
            foreground: false,
        })
    ) && env::var_os(CHILD_ENV).is_none()
}

/// Spawns the current executable as a background process, writes its PID file, and returns its PID.
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

/// Spawns a background daemon using explicit CLI arguments.
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

/// Reads and verifies the daemon PID file.
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

/// Stops the daemon process if it is running.
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

/// Removes a stale PID file when safe.
pub fn cleanup_stale_pid(pid_path: &Path) -> anyhow::Result<()> {
    if matches!(status(pid_path)?, DaemonStatus::Stale { .. }) {
        remove_pid_file(pid_path)?;
    }
    Ok(())
}

/// Returns true when this process is a daemon child.
pub fn is_daemon_child() -> bool {
    env::var_os(CHILD_ENV).is_some()
}

/// Writes the current process PID to the PID file.
pub fn write_current_pid(pid_path: &Path) -> anyhow::Result<()> {
    write_pid(pid_path, std::process::id())
}

/// Removes the PID file.
pub fn remove_pid_file(pid_path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(pid_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove {}", pid_path.display()))
        }
    }
}

/// Spawns current executable with supplied args.
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

/// Writes a PID file.
fn write_pid(pid_path: &Path, pid: u32) -> anyhow::Result<()> {
    if let Some(parent) = pid_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(pid_path, format!("{pid}\n"))
        .with_context(|| format!("failed to write {}", pid_path.display()))?;
    Ok(())
}

/// Reads a PID file.
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

/// Returns true if a process exists.
fn process_alive(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Sends SIGTERM to a process.
fn terminate(pid: u32) -> anyhow::Result<()> {
    let status = Command::new("kill").arg(pid.to_string()).status()?;
    anyhow::ensure!(status.success(), "failed to send SIGTERM to pid {pid}");
    Ok(())
}

/// Checks that a PID still points to a watcher daemon process.
fn looks_like_watcher_daemon(pid: u32) -> bool {
    let path = format!("/proc/{pid}/cmdline");
    let Ok(bytes) = fs::read(path) else {
        return true;
    };
    let command = String::from_utf8_lossy(&bytes).replace('\0', " ");
    command.contains("watcher") && command.contains("daemon") && command.contains("run")
}
