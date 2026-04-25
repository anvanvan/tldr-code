# M6 — VAL-006 — Daemon startup race (issue #14)

**Status:** SHIPPED
**Issue:** parcadei/tldr-code#14
**Worker:** kraken (M6 VAL-006)
**Starting HEAD:** 88ddac6

## Summary

Closed two TOCTOU windows in the daemon startup sequence:

1. **`start.rs::run_async`** called `cleanup_stale_pid` BEFORE
   `try_acquire_lock`, creating a window where two concurrent starts could
   both pass the staleness check before either acquired the flock. The
   flock-based `try_acquire_lock` already handles stale PIDs safely INSIDE
   the lock (open with `truncate(false)` → flock → truncate+write PID), so
   the pre-lock cleanup was redundant AND unsafe. **Fix:** removed the
   `cleanup_stale_pid` call (and the now-unused imports).

2. **`ipc.rs::IpcListener::bind_unix`** unconditionally `remove_file`d any
   existing socket before binding. A second daemon start that landed while
   a first daemon was already running would silently unlink the live first
   daemon's socket and bind a fresh one — clobbering the first daemon's IPC
   endpoint without any error surfaced to the second start. **Fix:**
   removed the unconditional unlink; `bind_unix` now attempts the bind
   directly and maps `io::ErrorKind::AddrInUse` to
   `DaemonError::AddressInUse { addr }`. Stale-socket cleanup remains the
   responsibility of the caller (start.rs) after a `check_socket_alive`
   liveness probe (which is already in place at start.rs ~L92).

`pid.rs` was NOT touched — its `cleanup_stale_pid` helper is no longer
called from the start path, and the helper itself remains correct for any
future callers (it is a simple `check_stale_pid + remove_file`; the TOCTOU
in the original triage was specific to the start.rs call site, not the
helper's internals).

## Files modified (2)

- `crates/tldr-cli/src/commands/daemon/start.rs`
  - Removed `check_stale_pid` + `cleanup_stale_pid` from imports.
  - Removed the pre-lock `if check_stale_pid { cleanup_stale_pid }` block.
  - Added a comment documenting the issue #14 rationale for the removal.
- `crates/tldr-cli/src/commands/daemon/ipc.rs`
  - Removed the `if socket_path.exists() { remove_file(...) }` block in
    `bind_unix`.
  - Mapped `io::ErrorKind::AddrInUse` from `UnixListener::bind` to
    `DaemonError::AddressInUse { addr: socket_path.display().to_string() }`,
    matching the existing pattern in `bind_tcp` (ipc.rs:247-253).

## New tests (3, all in `crates/tldr-cli/tests/val006_daemon_startup_race_test.rs`)

1. `second_bind_must_not_clobber_live_socket` — sequential reproducer:
   first `IpcListener::bind` succeeds, second bind on the same project
   while the first listener is still live MUST return `AddressInUse` /
   `SocketBindFailed`. Pre-fix: returned Ok (clobber). Post-fix: returns
   `AddressInUse`.
2. `concurrent_bind_unix_at_most_one_succeeds` — `std::sync::Barrier`
   released two threads racing to bind; at most one Ok permitted.
3. `start_rs_does_not_call_cleanup_stale_pid_before_lock` — structural
   regression guard reading start.rs source to ensure the redundant
   pre-lock cleanup is not reintroduced.

Synchronization is deterministic — `std::sync::Barrier` for the concurrent
test, sequential ordering for the clobber test, source-text inspection for
the structural guard. Zero `sleep` calls. Verified non-flaky over 5
consecutive full-suite runs.

## RED evidence (HEAD 88ddac6, before fix)

```
running 3 tests
test start_rs_does_not_call_cleanup_stale_pid_before_lock ... FAILED
test concurrent_bind_unix_at_most_one_succeeds ... ok
test second_bind_must_not_clobber_live_socket ... FAILED

---- second_bind_must_not_clobber_live_socket stdout ----
panicked at 'val006_daemon_startup_race_test.rs:73:18':
[bind succeeded twice — socket clobber] second IpcListener::bind on a project
whose first daemon is still live returned Ok, meaning bind_unix silently
unlinked-and-rebound the live socket (ipc.rs:219-223).
Expected DaemonError::AddressInUse / SocketBindFailed.

---- start_rs_does_not_call_cleanup_stale_pid_before_lock stdout ----
panicked at 'val006_daemon_startup_race_test.rs:144:5':
[TOCTOU regression] start.rs must not call cleanup_stale_pid() —
try_acquire_lock already handles stale PIDs safely inside the
flock-protected section. Calling cleanup_stale_pid before lock acquisition
reopens the TOCTOU window from issue #14.

test result: FAILED. 1 passed; 2 failed
```

Both failures name the bug literally: `bind succeeded twice — socket clobber`
and `TOCTOU regression`.

## GREEN evidence (after fix)

```
running 3 tests
test start_rs_does_not_call_cleanup_stale_pid_before_lock ... ok
test concurrent_bind_unix_at_most_one_succeeds ... ok
test second_bind_must_not_clobber_live_socket ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Flakiness: 5/5 GREEN over consecutive runs.

## Existing daemon test suite

- `cargo test -p tldr-cli --lib commands::daemon` — 201 passed; 0 failed.
- `cargo test -p tldr-cli --test daemon_test` — 28 passed; 0 failed; 42
  ignored (pre-existing ignored set, unrelated).

## Matrix

- `cargo test -p tldr-cli --release --test language_command_matrix` —
  234/234 passed.
- `cargo test -p tldr-cli --release --test exhaustive_matrix` — 676/730
  passed; 54 pre-existing failures are exactly the `test_embed_on_*` and
  `test_similar_on_*` suite documented under M3 evidence
  (`tldr embed`/`tldr semantic` subcommands renamed). Same baseline as
  M3-shipped (commit 48b03f9). Sum 910/964; the 54 are unrelated to daemon
  startup, IPC, or PID locking.

## Clippy

`cargo clippy -p tldr-cli --all-features --tests -- -D warnings`: clean.

Workspace-wide clippy currently fails in `crates/tldr-core/src/alias/solver.rs`
(`AliasSolver` initializer missing field `reverse_field_stores`) — this is
mid-flight M5 sibling work, not in M6 scope and outside the task's
disjointness rule (M5 owns `tldr-core/alias/solver.rs`).

## Constraint compliance

- Files modified: 2 (start.rs + ipc.rs); pid.rs intentionally NOT touched.
  Cap was ≤ 3.
- Race test deterministic: `std::sync::Barrier` + sequential ordering, no
  sleeps.
- Matrix did not regress (delta vs. M3 baseline: 0).
- No clippy warnings introduced in tldr-cli.
- No existing daemon test broken.

## Commit

`<sha-pending-commit>`
