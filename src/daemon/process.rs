//! Process liveness, termination, and daemon identity for PID-file checks.

#[cfg(not(windows))]
use std::process::Command;

/// Probes whether a process still exists.
///
/// Unix uses `kill -0`. Windows opens the process and checks `STILL_ACTIVE`.
///
/// # Arguments
///
/// - `pid`: process id to probe.
///
/// # Returns
///
/// `true` if the process exists; a failed probe is treated as not running.
///
/// # Examples
///
/// ```text
/// if process_alive(pid) { /* still running */ }
/// ```
pub(super) fn process_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        win32::process_alive(pid)
    }
    #[cfg(not(windows))]
    {
        Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}

/// Requests a running process to exit.
///
/// Unix sends SIGTERM. Windows calls `TerminateProcess`.
///
/// # Arguments
///
/// - `pid`: target process id.
///
/// # Returns
///
/// `Ok(())` when the signal or terminate call is delivered.
///
/// # Errors
///
/// Returns an error if the process cannot be opened or the terminate call
/// fails.
///
/// # Examples
///
/// ```text
/// terminate(pid)?;
/// ```
pub(super) fn terminate(pid: u32) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        win32::terminate(pid)
    }
    #[cfg(not(windows))]
    {
        let status = Command::new("kill").arg(pid.to_string()).status()?;
        anyhow::ensure!(status.success(), "failed to send SIGTERM to pid {pid}");
        Ok(())
    }
}

/// Checks whether a PID still points at a watcher daemon.
///
/// Unix reads `/proc/{pid}/cmdline` and requires `watcher`, `daemon`, and
/// `run`. Windows checks that the process image stem contains `watcher`.
/// If identity cannot be read, returns `true` conservatively so another
/// process's PID is not deleted by mistake.
///
/// # Arguments
///
/// - `pid`: process id to validate.
///
/// # Returns
///
/// `true` when the process looks like a watcher daemon, or when identity
/// cannot be read.
///
/// # Examples
///
/// ```text
/// if !looks_like_watcher_daemon(pid) { /* treat as stale */ }
/// ```
pub(super) fn looks_like_watcher_daemon(pid: u32) -> bool {
    #[cfg(windows)]
    {
        win32::looks_like_watcher_daemon(pid)
    }
    #[cfg(not(windows))]
    {
        let path = format!("/proc/{pid}/cmdline");
        let Ok(bytes) = std::fs::read(path) else {
            return true;
        };
        let command = String::from_utf8_lossy(&bytes).replace('\0', " ");
        command.contains("watcher") && command.contains("daemon") && command.contains("run")
    }
}

#[cfg(windows)]
mod win32 {
    use std::ffi::c_void;
    use std::path::Path;

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const PROCESS_TERMINATE: u32 = 0x0001;
    const STILL_ACTIVE: u32 = 259;

    unsafe extern "system" {
        unsafe fn OpenProcess(
            desired_access: u32,
            inherit_handle: i32,
            process_id: u32,
        ) -> *mut c_void;
        unsafe fn CloseHandle(handle: *mut c_void) -> i32;
        unsafe fn GetExitCodeProcess(handle: *mut c_void, exit_code: *mut u32) -> i32;
        unsafe fn TerminateProcess(handle: *mut c_void, exit_code: u32) -> i32;
        unsafe fn QueryFullProcessImageNameW(
            process: *mut c_void,
            flags: u32,
            exe_name: *mut u16,
            size: *mut u32,
        ) -> i32;
    }

    struct Handle(*mut c_void);

    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is an open kernel handle from `OpenProcess`.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    fn open(pid: u32, access: u32) -> Option<Handle> {
        // SAFETY: `OpenProcess` is a kernel32 import; a null return means failure.
        let raw = unsafe { OpenProcess(access, 0, pid) };
        if raw.is_null() {
            None
        } else {
            Some(Handle(raw))
        }
    }

    pub(super) fn process_alive(pid: u32) -> bool {
        let Some(handle) = open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
            return false;
        };
        let mut exit_code = 0_u32;
        // SAFETY: `handle` is a live process handle owned by `Handle`.
        let ok = unsafe { GetExitCodeProcess(handle.0, &mut exit_code) };
        ok != 0 && exit_code == STILL_ACTIVE
    }

    pub(super) fn terminate(pid: u32) -> anyhow::Result<()> {
        let handle = open(pid, PROCESS_TERMINATE)
            .ok_or_else(|| anyhow::anyhow!("failed to open pid {pid} for terminate"))?;
        // SAFETY: `handle` was opened with `PROCESS_TERMINATE`.
        let ok = unsafe { TerminateProcess(handle.0, 1) };
        anyhow::ensure!(ok != 0, "failed to terminate pid {pid}");
        Ok(())
    }

    pub(super) fn looks_like_watcher_daemon(pid: u32) -> bool {
        let Some(handle) = open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
            return true;
        };
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        // SAFETY: `buf` has `size` writable UTF-16 units for the image path.
        let ok = unsafe { QueryFullProcessImageNameW(handle.0, 0, buf.as_mut_ptr(), &mut size) };
        if ok == 0 {
            return true;
        }
        let len = usize::try_from(size).unwrap_or(0).min(buf.len());
        let path = String::from_utf16_lossy(&buf[..len]);
        Path::new(&path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| stem.to_ascii_lowercase().contains("watcher"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_is_alive() {
        assert!(process_alive(std::process::id()));
    }

    #[test]
    fn unused_pid_is_not_alive() {
        // `kill(2)` takes pid_t. u32::MAX becomes -1 ("every process") and
        // looks alive. 1_000_000_000 is outside Linux pid_max and Windows PID
        // space.
        assert!(!process_alive(1_000_000_000));
    }
}
