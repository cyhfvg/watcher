//! Windows console compatibility for ANSI colors and UTF-8 TUI output.
//!
//! cmd.exe and Windows PowerShell do not enable virtual terminal processing or
//! UTF-8 by default. Without that, tracing color codes print as raw escape
//! sequences, and the dashboard's CJK text plus box-drawing characters become
//! unreadable.

use std::io::IsTerminal;

/// Prepares the process console so ANSI colors and UTF-8 text can render.
///
/// On Windows this enables virtual terminal processing on stdout/stderr and
/// switches the console input/output code pages to UTF-8. On other platforms
/// this is a no-op. Safe to call more than once.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// none
///
/// # Examples
///
/// ```text
/// watcher::console::prepare();
/// ```
pub fn prepare() {
    #[cfg(windows)]
    windows::prepare();
}

/// Returns whether stdout should receive ANSI color codes.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// `true` when stdout is a terminal, `NO_COLOR` is unset, and the platform
/// can render ANSI sequences.
///
/// # Examples
///
/// ```text
/// fmt::layer().with_ansi(console::stdout_ansi_enabled());
/// ```
pub fn stdout_ansi_enabled() -> bool {
    ansi_enabled(std::io::stdout().is_terminal())
}

/// Decides whether a stream should emit ANSI color codes.
///
/// # Arguments
///
/// - `is_terminal`: whether the target stream is an interactive terminal.
///
/// # Returns
///
/// `true` when color output is safe for that stream.
///
/// # Examples
///
/// ```text
/// let enabled = ansi_enabled(std::io::stdout().is_terminal());
/// ```
fn ansi_enabled(is_terminal: bool) -> bool {
    decide_ansi(is_terminal, no_color_set(), platform_ansi_ok())
}

/// Pure ANSI decision used by runtime checks and tests.
///
/// # Arguments
///
/// - `is_terminal`: whether the output stream is a TTY.
/// - `no_color`: whether `NO_COLOR` is set to a non-empty value.
/// - `platform_ok`: whether this OS/console can render ANSI sequences.
///
/// # Returns
///
/// `true` only when all three conditions allow color.
///
/// # Examples
///
/// ```text
/// assert!(!decide_ansi(true, true, true));
/// ```
fn decide_ansi(is_terminal: bool, no_color: bool, platform_ok: bool) -> bool {
    is_terminal && !no_color && platform_ok
}

/// Returns whether `NO_COLOR` is set to a non-empty value.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// `true` when ANSI colors must be suppressed.
///
/// # Examples
///
/// ```text
/// let disabled = no_color_set();
/// ```
fn no_color_set() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
}

/// Returns whether this process can render ANSI on the current platform.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// `true` on Unix. On Windows, `true` after VT is enabled, or when `TERM` is
/// set to a non-dumb value (Git Bash / mintty).
///
/// # Examples
///
/// ```text
/// let ok = platform_ansi_ok();
/// ```
fn platform_ansi_ok() -> bool {
    #[cfg(windows)]
    {
        prepare();
        windows::vt_enabled() || term_supports_ansi()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// Returns whether `TERM` indicates an ANSI-capable emulator.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// `true` when `TERM` is set and is not `dumb`.
///
/// # Examples
///
/// ```text
/// let ok = term_supports_ansi();
/// ```
#[cfg(windows)]
fn term_supports_ansi() -> bool {
    std::env::var("TERM").is_ok_and(|term| term != "dumb")
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::sync::Once;
    use std::sync::atomic::{AtomicBool, Ordering};

    const STD_OUTPUT_HANDLE: u32 = -11_i32 as u32;
    const STD_ERROR_HANDLE: u32 = -12_i32 as u32;
    const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    const CP_UTF8: u32 = 65001;
    const INVALID_HANDLE_VALUE: isize = -1;

    static PREPARE: Once = Once::new();
    static VT_ENABLED: AtomicBool = AtomicBool::new(false);

    unsafe extern "system" {
        unsafe fn GetStdHandle(std_handle: u32) -> *mut c_void;
        unsafe fn GetConsoleMode(console: *mut c_void, mode: *mut u32) -> i32;
        unsafe fn SetConsoleMode(console: *mut c_void, mode: u32) -> i32;
        unsafe fn SetConsoleOutputCP(code_page: u32) -> i32;
        unsafe fn SetConsoleCP(code_page: u32) -> i32;
    }

    /// Enables UTF-8 and virtual terminal processing for this console.
    ///
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// none
    ///
    /// # Examples
    ///
    /// ```text
    /// windows::prepare();
    /// ```
    pub(super) fn prepare() {
        PREPARE.call_once(|| {
            // SAFETY: `SetConsoleCP` / `SetConsoleOutputCP` only change this
            // process console; a zero return is ignored when no console exists.
            unsafe {
                let _ = SetConsoleOutputCP(CP_UTF8);
                let _ = SetConsoleCP(CP_UTF8);
            }
            let stdout_ok = enable_vt(STD_OUTPUT_HANDLE);
            let stderr_ok = enable_vt(STD_ERROR_HANDLE);
            VT_ENABLED.store(stdout_ok || stderr_ok, Ordering::SeqCst);
        });
    }

    /// Returns whether VT processing was enabled on stdout or stderr.
    ///
    /// # Arguments
    ///
    /// none
    ///
    /// # Returns
    ///
    /// `true` after a successful `SetConsoleMode` on at least one std handle.
    ///
    /// # Examples
    ///
    /// ```text
    /// let ok = windows::vt_enabled();
    /// ```
    pub(super) fn vt_enabled() -> bool {
        prepare();
        VT_ENABLED.load(Ordering::SeqCst)
    }

    /// Enables virtual terminal processing on one standard handle.
    ///
    /// # Arguments
    ///
    /// - `std_handle`: `STD_OUTPUT_HANDLE` or `STD_ERROR_HANDLE`.
    ///
    /// # Returns
    ///
    /// `true` when the handle is a console and VT is now enabled.
    ///
    /// # Examples
    ///
    /// ```text
    /// let ok = enable_vt(STD_OUTPUT_HANDLE);
    /// ```
    fn enable_vt(std_handle: u32) -> bool {
        // SAFETY: `GetStdHandle` returns a borrowed console handle; a null or
        // invalid handle is rejected before `GetConsoleMode` / `SetConsoleMode`.
        unsafe {
            let handle = GetStdHandle(std_handle);
            if handle.is_null() || handle as isize == INVALID_HANDLE_VALUE {
                return false;
            }
            let mut mode = 0_u32;
            if GetConsoleMode(handle, &mut mode) == 0 {
                return false;
            }
            if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
                return true;
            }
            SetConsoleMode(
                handle,
                mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
            ) != 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_ansi_requires_tty_without_no_color() {
        assert!(!decide_ansi(false, false, true));
        assert!(!decide_ansi(true, true, true));
        assert!(!decide_ansi(true, false, false));
        assert!(decide_ansi(true, false, true));
    }

    #[test]
    fn prepare_is_idempotent() {
        prepare();
        prepare();
    }
}
