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

/// 判断当前子命令是否应以后台守护进程方式启动.
///
/// 仅 `daemon run` 且未指定 `--once` / `--foreground`, 并且本进程不是守护子进程时返回 `true`.
///
/// # 参数
///
/// - `command`: 已解析的 CLI 子命令.
///
/// # 返回
///
/// 需要先拉起后台子进程时返回 `true`.
///
/// # 示例
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

/// 以后台方式启动当前可执行文件, 写入 PID 文件并返回子进程 PID.
///
/// 子进程会继承当前命令行参数, 并通过环境变量避免再次自我拉起.
///
/// # 参数
///
/// - `pid_path`: 守护进程 PID 文件路径.
///
/// # 返回
///
/// 新后台进程的 PID.
///
/// # Errors
///
/// PID 文件已指向正在运行的守护进程, 清理陈旧 PID, 拉起子进程或写 PID 文件失败时返回错误.
///
/// # 示例
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

/// 使用显式 CLI 参数以后台方式启动守护进程.
///
/// # 参数
///
/// - `pid_path`: 守护进程 PID 文件路径.
/// - `args`: 传给子进程的参数, 通常是 `["daemon", "run"]`.
///
/// # 返回
///
/// 新后台进程的 PID.
///
/// # Errors
///
/// 已有守护进程在运行, 或拉起 / 写 PID 失败时返回错误.
///
/// # 示例
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

/// 读取并校验守护进程 PID 文件.
///
/// # 参数
///
/// - `pid_path`: PID 文件路径.
///
/// # 返回
///
/// [`DaemonStatus`]: 未运行, 正在运行, 或陈旧 / 不安全.
///
/// # Errors
///
/// 读取 PID 文件失败, 或文件内容不是合法 PID 时返回错误.
///
/// # 示例
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

/// 若守护进程正在运行则发送 SIGTERM 并等待退出.
///
/// # 参数
///
/// - `pid_path`: PID 文件路径.
///
/// # 返回
///
/// 停止成功时返回 [`DaemonStatus::NotRunning`]; 陈旧 PID 会被删除并返回 `Stale`;
/// 超时仍存活时返回 `Running`.
///
/// # Errors
///
/// 读取状态, 发送信号或删除 PID 文件失败时返回错误.
///
/// # 示例
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

/// 在安全时删除陈旧 PID 文件.
///
/// # 参数
///
/// - `pid_path`: PID 文件路径.
///
/// # 返回
///
/// 无需清理或清理成功时返回 `Ok(())`.
///
/// # Errors
///
/// 查询状态或删除文件失败时返回错误.
///
/// # 示例
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

/// 判断当前进程是否为守护子进程.
///
/// # 参数
///
/// 无.
///
/// # 返回
///
/// 环境变量 `WATCHER_DAEMON_CHILD` 存在时返回 `true`.
///
/// # 示例
///
/// ```
/// let _ = watcher::daemon::is_daemon_child();
/// ```
pub fn is_daemon_child() -> bool {
    env::var_os(CHILD_ENV).is_some()
}

/// 把当前进程 PID 写入 PID 文件.
///
/// # 参数
///
/// - `pid_path`: PID 文件路径.
///
/// # 返回
///
/// 写入成功时返回 `Ok(())`.
///
/// # Errors
///
/// 创建父目录或写入文件失败时返回错误.
///
/// # 示例
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

/// 删除 PID 文件; 文件不存在视为成功.
///
/// # 参数
///
/// - `pid_path`: PID 文件路径.
///
/// # 返回
///
/// 删除成功或不存在时返回 `Ok(())`.
///
/// # Errors
///
/// 删除时遇到除 `NotFound` 以外的 IO 错误时返回错误.
///
/// # 示例
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

/// 使用给定参数启动当前可执行文件.
///
/// # 参数
///
/// - `args`: 传给子进程的参数.
/// - `background`: 为 `true` 时断开标准流并设置守护子进程环境变量.
///
/// # 返回
///
/// 子进程 PID.
///
/// # Errors
///
/// 解析当前可执行文件路径, 打开 `/dev/null` 或 `spawn` 失败时返回错误.
///
/// # 示例
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

/// 把 PID 写入文件, 必要时创建父目录.
///
/// # 参数
///
/// - `pid_path`: PID 文件路径.
/// - `pid`: 要记录的进程号.
///
/// # 返回
///
/// 写入成功时返回 `Ok(())`.
///
/// # Errors
///
/// 创建目录或写文件失败时返回错误.
///
/// # 示例
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

/// 读取 PID 文件中的进程号.
///
/// # 参数
///
/// - `pid_path`: PID 文件路径.
///
/// # 返回
///
/// 文件不存在时返回 `None`, 否则返回解析出的 PID.
///
/// # Errors
///
/// 读文件失败或内容不是合法 `u32` 时返回错误.
///
/// # 示例
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

/// 用 `kill -0` 探测进程是否仍存在.
///
/// # 参数
///
/// - `pid`: 待探测的进程号.
///
/// # 返回
///
/// 进程存在时返回 `true`; `kill` 失败视为不存在.
///
/// # 示例
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

/// 向进程发送 SIGTERM.
///
/// # 参数
///
/// - `pid`: 目标进程号.
///
/// # 返回
///
/// 信号发送成功时返回 `Ok(())`.
///
/// # Errors
///
/// `kill` 启动失败或退出码非零时返回错误.
///
/// # 示例
///
/// ```text
/// terminate(pid)?;
/// ```
fn terminate(pid: u32) -> anyhow::Result<()> {
    let status = Command::new("kill").arg(pid.to_string()).status()?;
    anyhow::ensure!(status.success(), "failed to send SIGTERM to pid {pid}");
    Ok(())
}

/// 检查 PID 是否仍指向 watcher 守护进程.
///
/// 读取 `/proc/{pid}/cmdline`, 要求同时包含 `watcher`, `daemon` 和 `run`.
/// 无法读取 cmdline 时保守返回 `true`, 避免误删他人 PID.
///
/// # 参数
///
/// - `pid`: 待校验的进程号.
///
/// # 返回
///
/// 看起来是 watcher 守护进程, 或无法读取 cmdline 时返回 `true`.
///
/// # 示例
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
