//! VAL-006: Daemon startup race regression test (issue #14).
//!
//! Reproduces two TOCTOU windows in the daemon startup sequence:
//!
//! 1. `IpcListener::bind_unix` unconditionally `remove_file`s any existing
//!    socket before binding (ipc.rs:219-223). A second daemon-start sequence
//!    that lands while a first daemon is already running silently unlinks the
//!    first daemon's socket and binds a fresh one — clobbering the first
//!    daemon's IPC endpoint without any error.
//!
//! 2. `start.rs::run_async` calls `cleanup_stale_pid` BEFORE
//!    `try_acquire_lock`. The flock-protected pattern in `try_acquire_lock`
//!    already handles stale PIDs safely; calling `cleanup_stale_pid` first
//!    creates a TOCTOU window where two concurrent starts can both pass the
//!    staleness check before either acquires the lock.
//!
//! Synchronization: tests use either deterministic ordering (sequential
//! bind, then re-bind) or `std::sync::Barrier` to release concurrent
//! threads at the same instant. NO timing-based sleeps.
//!
//! Acceptance (post-fix): a second bind on a live socket must return
//! `DaemonError::AddressInUse` (or `SocketBindFailed` wrapping `EADDRINUSE`),
//! not silently clobber.

#![cfg(unix)]

use std::sync::{Arc, Barrier};
use std::thread;

use tldr_cli::commands::daemon::{DaemonError, IpcListener};

/// Helper: create a project tempdir whose canonical path is stable across
/// threads (so `compute_socket_path` returns identical values).
fn project_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("val006-race-")
        .tempdir()
        .expect("tempdir")
}

/// Sequential reproducer for the unconditional-unlink bug in `bind_unix`.
///
/// Pre-fix RED keyword: `bind succeeded twice` — the second `bind` returns
/// Ok, silently clobbering the first daemon's socket via the unlink path
/// in ipc.rs:219-223.
///
/// Post-fix GREEN: the second bind must return `AddressInUse` (or
/// `SocketBindFailed` wrapping `EADDRINUSE`), preserving the first daemon's
/// IPC endpoint.
#[test]
fn second_bind_must_not_clobber_live_socket() {
    let project = project_dir();
    let project_path = project.path().to_path_buf();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");

    // First daemon binds and holds its listener live.
    let first = rt
        .block_on(IpcListener::bind(&project_path))
        .expect("first bind should succeed");

    // Second start attempt — pre-fix this silently unlinks `first`'s socket
    // and binds a new one. Post-fix it must error.
    let second = rt.block_on(IpcListener::bind(&project_path));

    // Hold first listener live across the assertion so the OS sees a live
    // bind during the second attempt.
    drop(first);

    match second {
        Ok(_) => panic!(
            "[bind succeeded twice — socket clobber] second IpcListener::bind \
             on a project whose first daemon is still live returned Ok, meaning \
             bind_unix silently unlinked-and-rebound the live socket (ipc.rs:219-223). \
             Expected DaemonError::AddressInUse / SocketBindFailed."
        ),
        Err(DaemonError::AddressInUse { .. }) | Err(DaemonError::SocketBindFailed(_)) => {
            // Expected post-fix behavior.
        }
        Err(other) => panic!(
            "[unexpected error] second bind returned {other:?}; expected \
             DaemonError::AddressInUse or SocketBindFailed(EADDRINUSE)"
        ),
    }
}

/// Barrier-released concurrent reproducer: two threads racing to bind the
/// same project socket. Post-fix at least one must observe an
/// `AddressInUse` error rather than both succeeding.
#[test]
fn concurrent_bind_unix_at_most_one_succeeds() {
    let project = project_dir();
    let project_path = project.path().to_path_buf();

    let barrier = Arc::new(Barrier::new(2));

    let project_a = project_path.clone();
    let barrier_a = Arc::clone(&barrier);
    let handle_a = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt-a");
        barrier_a.wait();
        rt.block_on(IpcListener::bind(&project_a))
    });

    let project_b = project_path.clone();
    let barrier_b = Arc::clone(&barrier);
    let handle_b = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt-b");
        barrier_b.wait();
        rt.block_on(IpcListener::bind(&project_b))
    });

    let result_a = handle_a.join().expect("thread-a join");
    let result_b = handle_b.join().expect("thread-b join");

    let ok_count = [&result_a, &result_b].iter().filter(|r| r.is_ok()).count();
    assert!(
        ok_count <= 1,
        "[both binds succeeded] concurrent IpcListener::bind on the same project \
         produced {ok_count} successful binds; at most 1 is permitted. The losing \
         thread must observe AddressInUse, not silently rebind."
    );
}

/// Higher-level invariant: the start.rs path must NOT call `cleanup_stale_pid`
/// before lock acquisition. The `try_acquire_lock` flock pattern handles stale
/// PIDs safely inside the locked section; calling `cleanup_stale_pid` first
/// creates a TOCTOU window where two concurrent starts can both pass the
/// staleness check before either acquires the lock.
///
/// We assert this structurally by reading the start.rs source. This guards
/// against future regressions reintroducing the redundant pre-lock cleanup.
#[test]
fn start_rs_does_not_call_cleanup_stale_pid_before_lock() {
    let start_rs = include_str!("../src/commands/daemon/start.rs");
    assert!(
        !start_rs.contains("cleanup_stale_pid("),
        "[TOCTOU regression] start.rs must not call cleanup_stale_pid() — \
         try_acquire_lock already handles stale PIDs safely inside the flock-protected \
         section. Calling cleanup_stale_pid before lock acquisition reopens the \
         TOCTOU window from issue #14."
    );
}
