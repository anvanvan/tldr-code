//! PID file locking for daemon singleton enforcement
//!
//! This module provides cross-platform file locking to ensure only one daemon
//! instance runs per project. It addresses these security mitigations:
//!
//! - TIGER-P1-01: Atomic lock acquisition before PID write (prevents startup race)
//! - TIGER-P3-02: Acquire lock BEFORE reading existing PID (prevents TOCTOU attacks)
//!
//! # Security Pattern
//!
//! The lock acquisition follows this secure pattern:
//! 1. Create/open PID file
//! 2. Acquire exclusive non-blocking lock FIRST (before any reads)
//! 3. If lock fails, read PID and check if process is running
//! 4. If lock succeeds, truncate and write our PID
//! 5. Return guard that releases lock on drop
//!
//! This order is critical - acquiring the lock before reading prevents TOCTOU
//! (time-of-check to time-of-use) vulnerabilities where an attacker could
//! manipulate the PID file between our check and lock acquisition.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::commands::daemon::error::{DaemonError, DaemonResult};

// =============================================================================
// Path Computation
// =============================================================================

/// Compute a deterministic hash for a project path.
///
/// Uses MD5 hash of the canonicalized path, truncated to 8 hex characters.
/// This ensures the same project always gets the same PID/socket files.
pub fn compute_hash(project: &Path) -> String {
    // Canonicalize path if possible, otherwise use as-is
    let project_str = project
        .canonicalize()
        .unwrap_or_else(|_| project.to_path_buf())
        .to_string_lossy()
        .to_string();

    let digest = md5::compute(project_str.as_bytes());

    // Take first 8 hex characters
    format!("{:x}", digest)[..8].to_string()
}

/// Compute the PID file path for a project.
///
/// Path format: `{temp_dir}/tldr-{hash}.pid`
/// where hash = MD5(canonicalized_project_path)[:8]
pub fn compute_pid_path(project: &Path) -> PathBuf {
    let hash = compute_hash(project);
    let tmp_dir = std::env::temp_dir();
    tmp_dir.join(format!("tldr-{}.pid", hash))
}

/// Compute the socket path for a project (Unix).
///
/// Path format: `{temp_dir}/tldr-{hash}.sock`
/// Uses same hash as PID file for consistency.
#[cfg(unix)]
pub fn compute_socket_path(project: &Path) -> PathBuf {
    let hash = compute_hash(project);
    let tmp_dir = std::env::temp_dir();
    tmp_dir.join(format!("tldr-{}.sock", hash))
}

/// Compute the TCP port for a project (Windows).
///
/// Port range: 49152-59151 (dynamic/private port range)
/// Uses hash to deterministically map project to port.
#[cfg(windows)]
pub fn compute_tcp_port(project: &Path) -> u16 {
    let hash = compute_hash(project);
    let hash_int = u64::from_str_radix(&hash, 16).unwrap_or(0);
    49152 + (hash_int % 10000) as u16
}

// For cross-platform code that needs socket path on all platforms
#[cfg(not(unix))]
pub fn compute_socket_path(project: &Path) -> PathBuf {
    // On Windows, return a path that won't be used (TCP is used instead)
    let hash = compute_hash(project);
    let tmp_dir = std::env::temp_dir();
    tmp_dir.join(format!("tldr-{}.sock", hash))
}

// =============================================================================
// PID Guard (RAII lock holder)
// =============================================================================

/// Guard that holds the PID file lock and releases it on drop.
///
/// The guard ensures:
/// - Lock is held for the daemon's entire lifetime
/// - PID file is properly cleaned up on normal shutdown
/// - Lock is automatically released even on panic
pub struct PidGuard {
    /// The locked file handle
    _file: File,
    /// Path to the PID file (for cleanup)
    path: PathBuf,
    /// Our PID
    pid: u32,
}

impl PidGuard {
    /// Get the PID stored in this guard
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Get the path to the PID file
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        // Try to remove the PID file on cleanup
        // Ignore errors - the file might already be gone
        let _ = std::fs::remove_file(&self.path);

        // Lock is automatically released when file handle is dropped
    }
}

// =============================================================================
// Process Detection
// =============================================================================

/// Check if a process with the given PID is currently running.
///
/// # Platform-specific behavior
/// - Unix: Uses `kill(pid, 0)` which checks process existence without sending a signal
/// - Windows: Uses `OpenProcess` with limited query rights
#[cfg(unix)]
pub fn is_process_running(pid: u32) -> bool {
    // Signal 0 checks if process exists without actually sending a signal
    // Returns 0 on success (process exists), -1 on error
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

#[cfg(windows)]
pub fn is_process_running(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle == 0 {
            return false;
        }
        CloseHandle(handle);
        true
    }
}

// =============================================================================
// Current RSS (memory-watermark self-restart support)
// =============================================================================

/// Return this process's CURRENT resident-set size in bytes, or `None` if it
/// cannot be read on this platform.
///
/// This MUST be the live RSS, NEVER a lifetime peak (`ru_maxrss` on macOS is
/// the peak — keying a watermark on the peak would wedge a daemon in a restart
/// loop after a single transient spike). Mirrors Python's `_current_rss_mb`
/// in `tldr/model_server/server.py`, which reads the live value and returns a
/// safe sentinel on failure so an unreadable RSS can never trigger a spurious
/// self-exit.
///
/// # Platform-specific behavior
/// - Linux: parses `/proc/self/statm` field 2 (resident pages) × page size.
/// - macOS: `proc_pidinfo(PROC_PIDTASKINFO)` → `pti_resident_size`.
/// - Windows / other: `None` (watermark becomes a no-op).
#[cfg(target_os = "linux")]
pub fn current_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    // Fields: size resident shared text lib data dt (in pages)
    let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    // SC_PAGESIZE is the bytes-per-page; on Linux this is the resident
    // accounting unit for statm.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return None;
    }
    Some(resident_pages.saturating_mul(page_size as u64))
}

#[cfg(target_os = "macos")]
pub fn current_rss_bytes() -> Option<u64> {
    // proc_pidinfo(pid, PROC_PIDTASKINFO, ...) fills a `proc_taskinfo` whose
    // `pti_resident_size` is the CURRENT resident set (not a lifetime peak).
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    let pid = std::process::id() as libc::c_int;
    let ret = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTASKINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    // proc_pidinfo returns the number of bytes written; it must equal the
    // struct size for the read to be valid.
    if ret == size {
        Some(info.pti_resident_size)
    } else {
        None
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn current_rss_bytes() -> Option<u64> {
    // Windows / other: degrade to None — the RSS watermark becomes a no-op.
    None
}

// =============================================================================
// Ephemeral-root detection (cold-index skip support)
// =============================================================================

/// Bases that count as ephemeral roots. On macOS `/tmp` is a symlink to
/// `/private/tmp`, so both are listed (and paths are canonicalized before the
/// self-or-ancestor test) to match Python's `_EPHEMERAL_BASES`.
const EPHEMERAL_BASES: &[&str] = &["/private/tmp", "/tmp"];

/// True when `path` resolves under (or equals) `/tmp` or `/private/tmp`.
///
/// Mirrors Python's `tldr/daemon/ensure.py::_is_ephemeral_root`:
/// - A truthy `TLDR_INDEX_EPHEMERAL` env var (`1`/`true`/`yes`/`on`, any case,
///   trimmed) is an escape hatch that forces `false` so intentional /tmp
///   indexing (and tests) can still build an index.
/// - Otherwise the path is canonicalized (resolving the macOS `/tmp` →
///   `/private/tmp` symlink) before the self-or-ancestor membership test.
pub fn is_ephemeral_root(path: &Path) -> bool {
    let raw = std::env::var("TLDR_INDEX_EPHEMERAL").unwrap_or_default();
    if matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    ) {
        return false;
    }

    // Resolve symlinks where possible; fall back to the raw path if the target
    // does not yet exist (still want the prefix test to fire on /tmp paths).
    let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    for base in EPHEMERAL_BASES {
        let base_path = Path::new(base);
        if resolved == base_path || resolved.starts_with(base_path) {
            return true;
        }
    }
    false
}

// =============================================================================
// Lock Acquisition
// =============================================================================

/// Try to acquire an exclusive lock on the PID file.
///
/// # Security Pattern (TIGER-P1-01, TIGER-P3-02)
///
/// This function follows a secure lock acquisition pattern:
/// 1. Create/open file with read+write
/// 2. Acquire exclusive non-blocking lock FIRST
/// 3. If lock fails, read existing PID and check process status
/// 4. If lock succeeds, truncate file and write our PID
/// 5. Return guard that releases lock on drop
///
/// # Errors
///
/// - `AlreadyRunning { pid }` - Another daemon is running
/// - `LockFailed` - Could not acquire lock for other reasons
/// - `Io` - File system errors
pub fn try_acquire_lock(pid_path: &Path) -> DaemonResult<PidGuard> {
    // Ensure parent directory exists
    if let Some(parent) = pid_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Open or create the PID file
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false) // Don't truncate yet - we might fail to lock
        .open(pid_path)?;

    // Try to acquire exclusive lock FIRST (before reading)
    // This is critical for security - prevents TOCTOU attacks
    match try_lock_file(&file) {
        Ok(()) => {
            // Lock acquired successfully
            let our_pid = std::process::id();

            // Now safe to truncate and write our PID
            let mut file = file;
            file.set_len(0)?;
            file.seek(SeekFrom::Start(0))?;
            writeln!(file, "{}", our_pid)?;
            file.sync_all()?;

            Ok(PidGuard {
                _file: file,
                path: pid_path.to_path_buf(),
                pid: our_pid,
            })
        }
        Err(_) => {
            // Lock failed - another process holds it
            // Read the PID to report in error
            let existing_pid = read_pid_from_file(&file).unwrap_or(0);

            // Double-check the process is actually running
            if existing_pid > 0 && is_process_running(existing_pid) {
                Err(DaemonError::AlreadyRunning { pid: existing_pid })
            } else {
                // Stale lock - this shouldn't normally happen since we check the lock
                // But the process might have just died. Report as stale.
                Err(DaemonError::StalePidFile { pid: existing_pid })
            }
        }
    }
}

/// Read PID from an already-open file
fn read_pid_from_file(file: &File) -> Option<u32> {
    let mut file = file;
    let mut content = String::new();

    // Seek to start before reading
    if file.seek(SeekFrom::Start(0)).is_err() {
        return None;
    }

    if file.read_to_string(&mut content).is_err() {
        return None;
    }

    content.trim().parse().ok()
}

// =============================================================================
// Platform-specific locking
// =============================================================================

/// Try to acquire an exclusive non-blocking lock on a file.
#[cfg(unix)]
fn try_lock_file(file: &File) -> Result<(), std::io::Error> {
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();
    let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };

    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn try_lock_file(file: &File) -> Result<(), std::io::Error> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let handle = file.as_raw_handle() as HANDLE;

    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };

    let result = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1, // Lock 1 byte
            0,
            &mut overlapped,
        )
    };

    if result != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

// =============================================================================
// Stale Detection
// =============================================================================

/// Check if a PID file contains a stale PID (process no longer running).
///
/// Returns `true` if the file exists and contains a PID of a non-running process.
/// Returns `false` if file doesn't exist, is empty, or process is running.
pub fn check_stale_pid(pid_path: &Path) -> DaemonResult<bool> {
    // Try to read existing PID file
    let content = match std::fs::read_to_string(pid_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(DaemonError::Io(e)),
    };

    // Parse PID
    let pid: u32 = match content.trim().parse() {
        Ok(p) => p,
        Err(_) => return Ok(true), // Unparseable = stale
    };

    // Check if process is running
    Ok(!is_process_running(pid))
}

/// Clean up a stale PID file if it exists.
///
/// Only removes the file if it contains a PID of a non-running process.
/// This is safe to call even if the daemon is running - it will only
/// remove truly stale files.
pub fn cleanup_stale_pid(pid_path: &Path) -> DaemonResult<bool> {
    if check_stale_pid(pid_path)? {
        std::fs::remove_file(pid_path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_compute_hash_deterministic() {
        let project = PathBuf::from("/test/project");
        let hash1 = compute_hash(&project);
        let hash2 = compute_hash(&project);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 8);
    }

    #[test]
    fn test_compute_hash_different_projects() {
        let project1 = PathBuf::from("/test/project1");
        let project2 = PathBuf::from("/test/project2");
        let hash1 = compute_hash(&project1);
        let hash2 = compute_hash(&project2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_pid_path_format() {
        let project = PathBuf::from("/test/project");
        let pid_path = compute_pid_path(&project);

        let filename = pid_path.file_name().unwrap().to_str().unwrap();
        assert!(filename.starts_with("tldr-"));
        assert!(filename.ends_with(".pid"));
    }

    #[test]
    fn test_compute_socket_path_format() {
        let project = PathBuf::from("/test/project");
        let socket_path = compute_socket_path(&project);

        let filename = socket_path.file_name().unwrap().to_str().unwrap();
        assert!(filename.starts_with("tldr-"));
        assert!(filename.ends_with(".sock"));
    }

    #[test]
    fn test_pid_and_socket_share_hash() {
        let project = PathBuf::from("/test/project");
        let pid_path = compute_pid_path(&project);
        let socket_path = compute_socket_path(&project);

        // Extract hash from filenames
        let pid_name = pid_path.file_name().unwrap().to_str().unwrap();
        let socket_name = socket_path.file_name().unwrap().to_str().unwrap();

        // tldr-XXXXXXXX.pid -> XXXXXXXX
        let pid_hash = &pid_name[5..13];
        // tldr-XXXXXXXX.sock -> XXXXXXXX
        let socket_hash = &socket_name[5..13];

        assert_eq!(pid_hash, socket_hash);
    }

    #[test]
    fn test_try_acquire_lock_success() {
        let temp = TempDir::new().unwrap();
        let pid_path = temp.path().join("test.pid");

        let guard = try_acquire_lock(&pid_path).unwrap();

        // Verify PID was written
        let content = std::fs::read_to_string(&pid_path).unwrap();
        let written_pid: u32 = content.trim().parse().unwrap();
        assert_eq!(written_pid, std::process::id());
        assert_eq!(guard.pid(), std::process::id());
    }

    #[test]
    fn test_try_acquire_lock_already_locked() {
        let temp = TempDir::new().unwrap();
        let pid_path = temp.path().join("test.pid");

        // First lock
        let _guard1 = try_acquire_lock(&pid_path).unwrap();

        // Second lock attempt should fail
        let result = try_acquire_lock(&pid_path);
        assert!(result.is_err());
        match result {
            Err(DaemonError::AlreadyRunning { pid }) => {
                assert_eq!(pid, std::process::id());
            }
            _ => panic!("Expected AlreadyRunning error"),
        }
    }

    #[test]
    fn test_guard_cleanup_on_drop() {
        let temp = TempDir::new().unwrap();
        let pid_path = temp.path().join("test.pid");

        {
            let _guard = try_acquire_lock(&pid_path).unwrap();
            assert!(pid_path.exists());
        }

        // After guard is dropped, PID file should be removed
        assert!(!pid_path.exists());
    }

    #[test]
    fn test_is_process_running_self() {
        let our_pid = std::process::id();
        assert!(is_process_running(our_pid));
    }

    #[test]
    fn test_is_process_running_nonexistent() {
        // Use a very high PID that's unlikely to exist
        // PID 4194304 is above typical kernel max
        assert!(!is_process_running(4194304));
    }

    #[test]
    fn test_check_stale_pid_nonexistent_file() {
        let temp = TempDir::new().unwrap();
        let pid_path = temp.path().join("nonexistent.pid");

        let result = check_stale_pid(&pid_path).unwrap();
        assert!(!result); // File doesn't exist = not stale
    }

    #[test]
    fn test_check_stale_pid_running_process() {
        let temp = TempDir::new().unwrap();
        let pid_path = temp.path().join("test.pid");

        // Write our own PID (definitely running)
        std::fs::write(&pid_path, format!("{}", std::process::id())).unwrap();

        let result = check_stale_pid(&pid_path).unwrap();
        assert!(!result); // Our process is running = not stale
    }

    #[test]
    fn test_check_stale_pid_dead_process() {
        let temp = TempDir::new().unwrap();
        let pid_path = temp.path().join("test.pid");

        // Write a PID that doesn't exist
        std::fs::write(&pid_path, "4194304").unwrap();

        let result = check_stale_pid(&pid_path).unwrap();
        assert!(result); // Process not running = stale
    }

    #[test]
    fn test_cleanup_stale_pid() {
        let temp = TempDir::new().unwrap();
        let pid_path = temp.path().join("test.pid");

        // Write a stale PID
        std::fs::write(&pid_path, "4194304").unwrap();
        assert!(pid_path.exists());

        let cleaned = cleanup_stale_pid(&pid_path).unwrap();
        assert!(cleaned);
        assert!(!pid_path.exists());
    }

    #[test]
    fn test_cleanup_stale_pid_not_stale() {
        let temp = TempDir::new().unwrap();
        let pid_path = temp.path().join("test.pid");

        // Write our own PID (not stale)
        std::fs::write(&pid_path, format!("{}", std::process::id())).unwrap();

        let cleaned = cleanup_stale_pid(&pid_path).unwrap();
        assert!(!cleaned);
        assert!(pid_path.exists());
    }

    // =========================================================================
    // current_rss_bytes — CURRENT (not peak) RSS
    // =========================================================================

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_current_rss_bytes_is_some_and_nonzero() {
        let rss = current_rss_bytes();
        assert!(rss.is_some(), "RSS should be readable on this platform");
        assert!(rss.unwrap() > 0, "RSS should be > 0 for a live process");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_current_rss_bytes_reflects_current_not_peak() {
        // Allocate a large buffer and touch every page so it is genuinely
        // resident, then verify RSS climbs. (We do NOT assert it drops after
        // free — that is allocator/OS dependent — only that the reading is the
        // *current* live value, not a frozen lifetime peak.)
        let before = current_rss_bytes().unwrap();
        let mut buf: Vec<u8> = vec![0u8; 64 * 1024 * 1024]; // 64 MiB
        for i in (0..buf.len()).step_by(4096) {
            buf[i] = 1;
        }
        let during = current_rss_bytes().unwrap();
        // Keep buf alive across the second reading.
        std::hint::black_box(&buf);
        assert!(
            during >= before,
            "current RSS should not decrease after a large live allocation \
             (before={before}, during={during})"
        );
        // The allocation should be at least partially reflected.
        assert!(
            during > before,
            "current RSS should rise after touching 64 MiB \
             (before={before}, during={during})"
        );
    }

    // =========================================================================
    // is_ephemeral_root
    // =========================================================================

    // Env is process-global; serialize the env-mutating cases.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_is_ephemeral_root_tmp_subpath() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("TLDR_INDEX_EPHEMERAL");
        assert!(is_ephemeral_root(Path::new("/tmp/some-project")));
        assert!(is_ephemeral_root(Path::new("/private/tmp/some-project")));
        // Exact base also counts.
        assert!(is_ephemeral_root(Path::new("/private/tmp")));
    }

    #[test]
    fn test_is_ephemeral_root_non_tmp_is_false() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("TLDR_INDEX_EPHEMERAL");
        assert!(!is_ephemeral_root(Path::new("/home/user/project")));
        assert!(!is_ephemeral_root(Path::new("/Users/someone/dev/x")));
        assert!(!is_ephemeral_root(Path::new("/opt/app")));
    }

    #[test]
    fn test_is_ephemeral_root_escape_hatch_forces_false() {
        let _g = ENV_LOCK.lock().unwrap();
        for truthy in ["1", "true", "yes", "on", "TRUE", " On "] {
            std::env::set_var("TLDR_INDEX_EPHEMERAL", truthy);
            assert!(
                !is_ephemeral_root(Path::new("/tmp/some-project")),
                "escape hatch '{truthy}' should force false"
            );
        }
        // Falsy / empty values do NOT bypass.
        for falsy in ["", "0", "false", "no"] {
            std::env::set_var("TLDR_INDEX_EPHEMERAL", falsy);
            assert!(
                is_ephemeral_root(Path::new("/tmp/some-project")),
                "value '{falsy}' must not bypass the guard"
            );
        }
        std::env::remove_var("TLDR_INDEX_EPHEMERAL");
    }

    #[cfg(windows)]
    #[test]
    fn test_compute_tcp_port_range() {
        let project = PathBuf::from("/test/project");
        let port = compute_tcp_port(&project);
        assert!(port >= 49152);
        assert!(port < 59152);
    }

    #[cfg(windows)]
    #[test]
    fn test_compute_tcp_port_deterministic() {
        let project = PathBuf::from("/test/project");
        let port1 = compute_tcp_port(&project);
        let port2 = compute_tcp_port(&project);
        assert_eq!(port1, port2);
    }
}
