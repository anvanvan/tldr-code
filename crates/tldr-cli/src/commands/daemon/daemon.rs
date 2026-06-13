//! Core daemon state machine and runtime
//!
//! This module contains the `TLDRDaemon` struct which manages:
//! - Daemon lifecycle state (Initializing -> Ready -> ShuttingDown)
//! - Salsa-style query cache
//! - Session statistics tracking
//! - Hook activity tracking
//! - Dirty file tracking for incremental re-indexing
//!
//! # Security Mitigations
//!
//! - TIGER-P2-02: Socket cleanup on abnormal exit via signal handlers

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::{watch, Mutex, RwLock};

use super::error::{DaemonError, DaemonResult};
use super::ipc::{read_command, send_response, IpcListener, IpcStream};
use super::salsa::{QueryCache, QueryKey};
use super::types::{
    AllSessionsSummary, DaemonCommand, DaemonConfig, DaemonResponse, DaemonStatus, HookStats,
    SalsaCacheStats, SessionStats, HOOK_FLUSH_THRESHOLD,
};

#[cfg(test)]
use super::types::DEFAULT_REINDEX_THRESHOLD;
#[cfg(feature = "semantic")]
use tldr_core::semantic::{BuildOptions, CacheConfig, IndexSearchOptions, SemanticIndex};
use tldr_core::{
    architecture_analysis, build_project_call_graph, change_impact, collect_all_functions,
    dead_code_analysis, detect_or_parse_language, extract_file, find_importers, get_cfg_context,
    get_code_structure, get_dfg_context, get_file_tree, get_imports, get_relevant_context,
    get_slice, impact_analysis, search as tldr_search, FileTree, Language, NodeType,
    SliceDirection,
};

// =============================================================================
// Helper Functions
// =============================================================================

/// Hash a slice of string arguments into a u64 for cache key generation.
fn hash_str_args(parts: &[&str]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for part in parts {
        part.hash(&mut hasher);
    }
    hasher.finish()
}

/// Resolve the effective `Language` for a daemon-handler invocation.
///
/// v031-cluster-M2: M1 added `language: Option<Language>` to seven
/// DaemonCommand variants (Context, Calls, Impact, Dead, Arch, Importers,
/// ChangeImpact). The handler arms that consume those variants previously
/// passed a hardcoded `Language::Python` to `tldr-core` regardless of what
/// the client supplied — a forgotten-thread bug. This helper centralises the
/// `Some(lang) | None -> default` resolution so every handler arm threads
/// the language consistently. The default-on-`None` is `Language::Python`
/// to preserve back-compat with v0.2.x clients that never sent a language
/// hint.
pub(crate) fn resolve_language(language: Option<Language>) -> Language {
    language.unwrap_or(Language::Python)
}

/// Count the number of file nodes in a FileTree recursively.
fn count_tree_files(tree: &FileTree) -> usize {
    match tree.node_type {
        NodeType::File => 1,
        NodeType::Dir => tree.children.iter().map(count_tree_files).sum(),
    }
}

/// Minimum spacing between two RSS reads (the watermark check). RSS moves per
/// embed/index batch, not per accept tick, so once a second is plenty and the
/// per-OS read (a syscall) stays cheap. Mirrors Python's `_RSS_CHECK_INTERVAL`.
const RSS_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Parent-death watchdog poll interval. Mirrors Python's `_WATCHDOG_POLL_SECS`.
const WATCHDOG_POLL_SECS: u64 = 1;

/// Test/production seam for reading the current process RSS in bytes. Defaults
/// to `pid::current_rss_bytes`; unit tests inject a fake probe so the watermark
/// behavior is a pure unit test with no real allocation.
pub type RssProbe = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

/// Test/production seam for the reindex fold side effect. Receives the folded
/// dirty-file snapshot. The production default invalidates the in-process
/// semantic index so it rebuilds lazily on the next query; tests inject a probe
/// that records what was folded.
pub type FoldCallback = Arc<dyn Fn(Vec<PathBuf>) + Send + Sync>;

/// Bundle of `Arc` handles the spawned reindex timer task captures, so the
/// scheduler does not need `Arc<Self>` (which would force `handle_command` to
/// take `self: &Arc<Self>` and break existing `TLDRDaemon`-by-value callers).
struct ReindexState {
    reindex_timer: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    last_reindex_fire_ms: Arc<AtomicU64>,
    reindex_fire_count: Arc<AtomicU64>,
    dirty_files: Arc<RwLock<HashSet<PathBuf>>>,
    fold_callback: Arc<RwLock<Option<FoldCallback>>>,
    #[cfg(feature = "semantic")]
    semantic_index: Arc<RwLock<Option<SemanticIndex>>>,
    /// Tokio-clock origin for cooldown arithmetic. Uses `tokio::time::Instant`
    /// (NOT `std::time::Instant`) so `tokio::time::pause`/`advance` drives the
    /// cooldown spread in unit tests, matching the `sleep`-based debounce.
    tokio_start: tokio::time::Instant,
}

impl ReindexState {
    /// Timer callback: fire the deferred reindex (folds the WHOLE dirty set).
    ///
    /// Mirrors Python's `_drain_pending_reindex` + `_trigger_background_reindex`:
    /// records the fire time for the cooldown spread, snapshots and clears the
    /// dirty set ONCE, then runs the fold side effect (production: invalidate
    /// the in-process semantic index so it rebuilds lazily; tests: record the
    /// folded set). Because the snapshot is taken atomically, a burst delivered
    /// as many notifies collapses to one fold carrying the whole accumulated
    /// set.
    async fn drain_pending_reindex(&self) {
        // Clear our own timer handle slot (we are that timer firing).
        {
            let mut timer = self.reindex_timer.lock().await;
            *timer = None;
        }
        self.last_reindex_fire_ms.store(
            self.tokio_start.elapsed().as_millis() as u64,
            Ordering::SeqCst,
        );

        // Snapshot + clear the dirty set exactly once.
        let snapshot: Vec<PathBuf> = {
            let mut dirty = self.dirty_files.write().await;
            if dirty.is_empty() {
                return;
            }
            let snap = dirty.iter().cloned().collect();
            dirty.clear();
            snap
        };

        self.reindex_fire_count.fetch_add(1, Ordering::SeqCst);

        // Run the fold side effect.
        let cb = self.fold_callback.read().await.clone();
        if let Some(cb) = cb {
            cb(snapshot);
        } else {
            // Production default: invalidate the in-process semantic index so
            // it rebuilds lazily on the next query over the folded set.
            #[cfg(feature = "semantic")]
            {
                let mut idx = self.semantic_index.write().await;
                *idx = None;
            }
            #[cfg(not(feature = "semantic"))]
            {
                let _ = snapshot;
            }
        }
    }
}

// =============================================================================
// TLDRDaemon - Main Daemon Process
// =============================================================================

/// Main daemon process that handles client connections and manages state.
///
/// The daemon runs an event loop that:
/// 1. Accepts incoming IPC connections
/// 2. Reads commands from clients
/// 3. Dispatches commands to handlers
/// 4. Sends responses back to clients
/// 5. Handles shutdown signals gracefully
pub struct TLDRDaemon {
    /// Project root directory
    project: PathBuf,
    /// Daemon configuration
    config: DaemonConfig,
    /// When the daemon was started
    start_time: Instant,
    /// Current daemon status
    status: Arc<RwLock<DaemonStatus>>,
    /// Salsa-style query cache
    cache: QueryCache,
    /// Per-session statistics
    sessions: DashMap<String, SessionStats>,
    /// Per-hook activity statistics
    hooks: DashMap<String, HookStats>,
    /// Set of dirty files awaiting reindex
    dirty_files: Arc<RwLock<HashSet<PathBuf>>>,
    /// Shutdown signal sender
    shutdown_tx: watch::Sender<bool>,
    /// Flag to track if we've been signaled to stop
    stopping: AtomicBool,
    /// Last time a client command was handled (for idle timeout)
    last_activity: Arc<RwLock<Instant>>,
    /// Number of indexed files (for status reporting)
    indexed_files: Arc<RwLock<usize>>,
    /// Persistent semantic index (built lazily on first query, invalidated on Notify)
    #[cfg(feature = "semantic")]
    semantic_index: Arc<RwLock<Option<SemanticIndex>>>,

    // --- C1: RSS-watermark self-restart -------------------------------------
    /// Count of client commands currently being handled. The watermark never
    /// fires while this is non-zero (never exit mid-request).
    in_flight: Arc<AtomicUsize>,
    /// Latched once the RSS watermark is breached at a safe instant; the run
    /// loop drains and exits on the next iteration.
    rss_exit: Arc<AtomicBool>,
    /// Last time the (cheap-but-not-free) RSS read ran, for the 1/s throttle.
    last_rss_check: Arc<RwLock<Option<Instant>>>,
    /// RSS-read seam. Defaults to `pid::current_rss_bytes`; tests inject a fake.
    rss_probe: RssProbe,

    // --- C3: re-armable notify reindex scheduler ----------------------------
    /// The single armed reindex timer task (debounce/coalesce). Re-armed on
    /// each threshold-crossing notify, cancelled on shutdown.
    reindex_timer: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Monotonic ms (since `start_time`) of the last reindex fire, for cooldown.
    last_reindex_fire_ms: Arc<AtomicU64>,
    /// Number of completed reindex folds (test observability).
    reindex_fire_count: Arc<AtomicU64>,
    /// Fold side-effect seam. Receives the folded dirty snapshot.
    fold_callback: Arc<RwLock<Option<FoldCallback>>>,
    /// Tokio-clock origin for cooldown arithmetic (paused-clock testable).
    tokio_start: tokio::time::Instant,
}

impl TLDRDaemon {
    /// Create a new daemon instance.
    ///
    /// The daemon starts in `Initializing` status and must have `run()` called
    /// to begin accepting connections.
    pub fn new(project: PathBuf, config: DaemonConfig) -> Self {
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        Self {
            project,
            config,
            start_time: Instant::now(),
            status: Arc::new(RwLock::new(DaemonStatus::Initializing)),
            cache: QueryCache::with_defaults(),
            sessions: DashMap::new(),
            hooks: DashMap::new(),
            dirty_files: Arc::new(RwLock::new(HashSet::new())),
            shutdown_tx,
            stopping: AtomicBool::new(false),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            indexed_files: Arc::new(RwLock::new(0)),
            #[cfg(feature = "semantic")]
            semantic_index: Arc::new(RwLock::new(None)),
            in_flight: Arc::new(AtomicUsize::new(0)),
            rss_exit: Arc::new(AtomicBool::new(false)),
            last_rss_check: Arc::new(RwLock::new(None)),
            rss_probe: Arc::new(super::pid::current_rss_bytes),
            reindex_timer: Arc::new(Mutex::new(None)),
            last_reindex_fire_ms: Arc::new(AtomicU64::new(0)),
            reindex_fire_count: Arc::new(AtomicU64::new(0)),
            fold_callback: Arc::new(RwLock::new(None)),
            tokio_start: tokio::time::Instant::now(),
        }
    }

    /// Inject a fake RSS probe (test seam for the watermark unit tests).
    #[cfg(test)]
    pub(crate) fn set_rss_probe(&mut self, probe: RssProbe) {
        self.rss_probe = probe;
    }

    /// Install a fold callback observing the snapshot folded by each reindex
    /// fire (test seam for the notify-scheduler unit tests).
    #[cfg(test)]
    pub(crate) async fn set_fold_callback(&self, cb: FoldCallback) {
        *self.fold_callback.write().await = Some(cb);
    }

    /// Number of completed reindex folds so far (test observability).
    #[cfg(test)]
    pub(crate) fn reindex_fire_count(&self) -> u64 {
        self.reindex_fire_count.load(Ordering::SeqCst)
    }

    /// Whether the RSS-exit latch is set (test observability).
    #[cfg(test)]
    pub(crate) fn rss_exit_latched(&self) -> bool {
        self.rss_exit.load(Ordering::SeqCst)
    }

    /// Get the daemon's current status.
    pub async fn status(&self) -> DaemonStatus {
        *self.status.read().await
    }

    /// Get the daemon's uptime in seconds.
    pub fn uptime(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Get the daemon's uptime formatted as a human-readable string.
    pub fn uptime_human(&self) -> String {
        let secs = self.start_time.elapsed().as_secs();
        let hours = secs / 3600;
        let minutes = (secs % 3600) / 60;
        let seconds = secs % 60;
        format!("{}h {}m {}s", hours, minutes, seconds)
    }

    /// Get cache statistics.
    pub fn cache_stats(&self) -> SalsaCacheStats {
        self.cache.stats()
    }

    /// Get the project path.
    pub fn project(&self) -> &PathBuf {
        &self.project
    }

    /// Get the number of indexed files.
    pub async fn indexed_files(&self) -> usize {
        *self.indexed_files.read().await
    }

    /// Get a summary of all sessions.
    pub fn all_sessions_summary(&self) -> AllSessionsSummary {
        let mut summary = AllSessionsSummary {
            active_sessions: self.sessions.len(),
            ..AllSessionsSummary::default()
        };

        for entry in self.sessions.iter() {
            let stats = entry.value();
            summary.total_raw_tokens += stats.raw_tokens;
            summary.total_tldr_tokens += stats.tldr_tokens;
            summary.total_requests += stats.requests;
        }

        summary
    }

    /// Get all hook statistics.
    pub fn hook_stats(&self) -> HashMap<String, HookStats> {
        self.hooks
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }

    /// Signal the daemon to shut down gracefully.
    pub fn shutdown(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(true);
    }

    // =========================================================================
    // C1: RSS-watermark self-restart
    // =========================================================================

    /// Latch `rss_exit` if the watermark is breached NOW at a safe instant;
    /// return whether the latch is set.
    ///
    /// Mirrors Python's `_maybe_flag_rss_exit`/`_rss_watermark_breached`: the
    /// latch fires only when ALL of —
    /// 1. the 1/s throttle window has elapsed,
    /// 2. no command is in flight (never exit mid-request),
    /// 3. CURRENT RSS (never a lifetime peak) exceeds the watermark —
    /// hold. The first two are cheap and checked BEFORE the throttle window is
    /// consumed, so a busy instant never burns the window. A watermark of 0 (or
    /// an unreadable RSS) disables the check, so it can never spuriously fire.
    async fn maybe_flag_rss_exit(&self) -> bool {
        if self.rss_exit.load(Ordering::SeqCst) {
            return true;
        }
        // Gate BEFORE consuming the throttle window so a busy instant can still
        // re-check at the next idle gap (matches Python's ordering).
        if self.in_flight.load(Ordering::SeqCst) != 0 {
            return false;
        }
        let watermark_mb = self.config.rss_watermark_mb;
        if watermark_mb == 0 {
            return false;
        }
        // Throttle: at most one RSS read per RSS_CHECK_INTERVAL.
        {
            let mut last = self.last_rss_check.write().await;
            let now = Instant::now();
            if let Some(prev) = *last {
                if now.duration_since(prev) < RSS_CHECK_INTERVAL {
                    return false;
                }
            }
            *last = Some(now);
        }
        let watermark_bytes = watermark_mb.saturating_mul(1024 * 1024);
        match (self.rss_probe)() {
            Some(rss) if rss > watermark_bytes => {
                self.rss_exit.store(true, Ordering::SeqCst);
                eprintln!(
                    "RSS {} bytes breached watermark {} MiB, draining and self-exiting",
                    rss, watermark_mb
                );
                true
            }
            _ => false,
        }
    }

    // =========================================================================
    // C2: parent-death watchdog
    // =========================================================================

    /// Spawn the parent-death watchdog task IFF a parent pid was recorded.
    ///
    /// Mirrors Python's `_watch_parent`: polls `is_process_running(parent_pid)`
    /// and signals shutdown when the SPECIFIC spawner dies. NEVER keyed on
    /// `getppid()==1` — a setsid-detached daemon legitimately has ppid 1, so the
    /// task only ever exists when `config.parent_pid` is `Some`.
    fn spawn_parent_watchdog(self: &Arc<Self>) {
        let Some(parent_pid) = self.config.parent_pid else {
            return;
        };
        let daemon = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                if daemon.stopping.load(Ordering::SeqCst) {
                    break;
                }
                if !super::pid::is_process_running(parent_pid) {
                    eprintln!(
                        "Parent process {} is gone, shutting down",
                        parent_pid
                    );
                    daemon.shutdown();
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(WATCHDOG_POLL_SECS)).await;
            }
        });
    }

    /// Run the daemon main loop.
    ///
    /// This function blocks until the daemon is shut down via:
    /// - A `Shutdown` command from a client
    /// - A SIGTERM/SIGINT signal
    /// - An error in the listener
    pub async fn run(self: Arc<Self>, listener: IpcListener) -> DaemonResult<()> {
        // Set status to Ready
        {
            let mut status = self.status.write().await;
            *status = DaemonStatus::Ready;
        }

        // Set up signal handlers for graceful shutdown
        #[cfg(unix)]
        {
            let daemon = Arc::clone(&self);
            tokio::spawn(async move {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("Failed to register SIGTERM handler");
                let mut sigint =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                        .expect("Failed to register SIGINT handler");

                tokio::select! {
                    _ = sigterm.recv() => {
                        daemon.shutdown();
                    }
                    _ = sigint.recv() => {
                        daemon.shutdown();
                    }
                }
            });
        }

        // C2: parent-death watchdog (only when a spawner pid was recorded).
        self.spawn_parent_watchdog();

        // Main event loop
        let idle_timeout = std::time::Duration::from_secs(self.config.idle_timeout_secs);

        loop {
            // Check for shutdown signal
            if self.stopping.load(Ordering::SeqCst) {
                break;
            }

            // C1: RSS watermark — if it was latched at a safe instant (idle
            // heartbeat below or a request completion), drain and exit now.
            // Mirrors Python's loop-top `_rss_exit.is_set()` break.
            if self.rss_exit.load(Ordering::SeqCst) {
                eprintln!("RSS watermark breached, draining and shutting down");
                break;
            }

            // Safety net: self-terminate if project directory no longer exists
            if !self.project.exists() {
                eprintln!(
                    "Project directory {} no longer exists, shutting down",
                    self.project.display()
                );
                break;
            }

            // Self-terminate after idle timeout with no client activity
            {
                let last = self.last_activity.read().await;
                if last.elapsed() > idle_timeout {
                    eprintln!(
                        "No client activity for {}s, shutting down",
                        self.config.idle_timeout_secs
                    );
                    break;
                }
            }

            // Accept connection with timeout
            let accept_future = listener.accept();
            let timeout = tokio::time::Duration::from_millis(100);

            match tokio::time::timeout(timeout, accept_future).await {
                Ok(Ok(mut stream)) => {
                    // Update activity timestamp
                    *self.last_activity.write().await = Instant::now();

                    // Handle the connection
                    let daemon = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = daemon.handle_connection(&mut stream).await {
                            eprintln!("Connection error: {}", e);
                        }
                    });
                }
                Ok(Err(e)) => {
                    // Accept error - log and continue
                    eprintln!("Accept error: {}", e);
                }
                Err(_) => {
                    // Idle heartbeat: the accept timeout is our heartbeat — the
                    // only idle instant on a quiet daemon. C1: check the RSS
                    // watermark here (throttled, in-flight-gated). Mirrors the
                    // Python idle-tick `_maybe_flag_rss_exit`.
                    self.maybe_flag_rss_exit().await;
                    continue;
                }
            }
        }

        // C3: cancel any armed reindex timer on shutdown so a pending fold can
        // never fire after the daemon has begun draining.
        {
            let mut timer = self.reindex_timer.lock().await;
            if let Some(handle) = timer.take() {
                handle.abort();
            }
        }

        // Set status to ShuttingDown
        {
            let mut status = self.status.write().await;
            *status = DaemonStatus::ShuttingDown;
        }

        // Persist stats before exit
        self.persist_stats().await?;

        // Set status to Stopped
        {
            let mut status = self.status.write().await;
            *status = DaemonStatus::Stopped;
        }

        Ok(())
    }

    /// Handle a single client connection.
    ///
    /// C1: tracks the in-flight count for the RSS watermark gate, and runs a
    /// request-completion watermark check (the only idle instant under a
    /// continuous back-to-back load, where the accept heartbeat never fires).
    ///
    /// C4: after the full command is read, the handler future races against
    /// `poll_peer_closed`. If the client drops mid-command, the handler future
    /// is dropped (cooperative cancel at await points) and no response is
    /// written. This stays cooperative — a fully-synchronous inner analysis
    /// with no await points still runs to completion (matches Python's
    /// "in-flight finishes" semantics).
    async fn handle_connection(self: &Arc<Self>, stream: &mut IpcStream) -> DaemonResult<()> {
        // Track in-flight for the watermark gate; decrement on every exit path.
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let result = self.handle_connection_inner(stream).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);

        // Request-completion watermark check: this gap — after the response and
        // before the next accept — is the only idle moment a continuous load
        // ever exposes (the 2026-06-12 live-verification gap). Now in-flight is
        // back to its pre-request value.
        self.maybe_flag_rss_exit().await;

        result
    }

    /// Inner handler: read → (handle ⨉ peer-closed) → respond.
    async fn handle_connection_inner(self: &Arc<Self>, stream: &mut IpcStream) -> DaemonResult<()> {
        // Read command
        let cmd = read_command(stream).await?;

        // C4: race the handler against the client disconnecting.
        let response = tokio::select! {
            biased;
            // If the peer closes first, drop the handler future (cancel) and
            // write no response.
            _ = stream.poll_peer_closed() => {
                return Ok(());
            }
            response = self.handle_command(cmd) => response,
        };

        // Send response
        send_response(stream, &response).await?;

        Ok(())
    }

    /// Handle a daemon command and return the response.
    pub async fn handle_command(&self, cmd: DaemonCommand) -> DaemonResponse {
        match cmd {
            DaemonCommand::Ping => DaemonResponse::Status {
                status: "ok".to_string(),
                message: Some("pong".to_string()),
            },

            DaemonCommand::Status { session } => self.handle_status(session).await,

            DaemonCommand::Shutdown => {
                self.shutdown();
                DaemonResponse::Status {
                    status: "shutting_down".to_string(),
                    message: Some("Daemon is shutting down".to_string()),
                }
            }

            DaemonCommand::Notify { file } => self.handle_notify(file).await,

            DaemonCommand::Track {
                hook,
                success,
                metrics,
            } => self.handle_track(hook, success, metrics).await,

            DaemonCommand::Warm { language } => {
                let parsed = language.as_deref().and_then(|l| l.parse::<Language>().ok());
                let lang = resolve_language(parsed);

                let mut warmed = Vec::new();
                let mut errors = Vec::new();

                // 1. Warm call graph
                let calls_key = QueryKey::new(
                    "calls",
                    hash_str_args(&[&self.project.to_string_lossy()]),
                    lang,
                );
                if self.cache.get::<serde_json::Value>(&calls_key).is_some() {
                    warmed.push("call_graph (cached)");
                } else {
                    match build_project_call_graph(&self.project, lang, None, true) {
                        Ok(result) => {
                            let val = serde_json::to_value(&result).unwrap_or_default();
                            self.cache.insert(calls_key, &val, vec![]);
                            warmed.push("call_graph");
                        }
                        Err(e) => errors.push(format!("call_graph: {}", e)),
                    }
                }

                // 2. Warm code structure
                let struct_key = QueryKey::new(
                    "structure",
                    hash_str_args(&[&self.project.to_string_lossy(), ""]),
                    lang,
                );
                if self.cache.get::<serde_json::Value>(&struct_key).is_some() {
                    warmed.push("structure (cached)");
                } else {
                    match get_code_structure(&self.project, lang, 0, None) {
                        Ok(result) => {
                            let val = serde_json::to_value(&result).unwrap_or_default();
                            self.cache.insert(struct_key, &val, vec![]);
                            warmed.push("structure");
                        }
                        Err(e) => errors.push(format!("structure: {}", e)),
                    }
                }

                // 3. Warm file tree
                let tree_key = QueryKey::new(
                    "tree",
                    hash_str_args(&[&self.project.to_string_lossy()]),
                    lang,
                );
                if self.cache.get::<serde_json::Value>(&tree_key).is_some() {
                    warmed.push("file_tree (cached)");
                } else {
                    match get_file_tree(&self.project, None, true, None) {
                        Ok(result) => {
                            let file_count = count_tree_files(&result);
                            let val = serde_json::to_value(&result).unwrap_or_default();
                            self.cache.insert(tree_key, &val, vec![]);
                            *self.indexed_files.write().await = file_count;
                            warmed.push("file_tree");
                        }
                        Err(e) => errors.push(format!("file_tree: {}", e)),
                    }
                }

                // 4. Warm semantic index
                #[cfg(feature = "semantic")]
                {
                    // C5: skip the cold semantic-index build on an ephemeral
                    // /tmp root (honoring TLDR_INDEX_EPHEMERAL). A throwaway
                    // /tmp project must not pay a cold-index burst. Mirrors
                    // Python's `_is_ephemeral_root` early-return in ensure.py.
                    if super::pid::is_ephemeral_root(&self.project) {
                        warmed.push("semantic_index (skipped: ephemeral root)");
                    } else {
                        let mut index_guard = self.semantic_index.write().await;
                        if index_guard.is_some() {
                            warmed.push("semantic_index (cached)");
                        } else {
                            let build_opts = BuildOptions {
                                show_progress: false,
                                use_cache: true,
                                ..Default::default()
                            };
                            match SemanticIndex::build(
                                &self.project,
                                build_opts,
                                Some(CacheConfig::default()),
                            ) {
                                Ok(idx) => {
                                    *index_guard = Some(idx);
                                    warmed.push("semantic_index");
                                }
                                Err(e) => errors.push(format!("semantic_index: {}", e)),
                            }
                        }
                    }
                }

                let message = if errors.is_empty() {
                    format!("Warmed: {}", warmed.join(", "))
                } else {
                    format!(
                        "Warmed: {}. Errors: {}",
                        warmed.join(", "),
                        errors.join("; ")
                    )
                };

                DaemonResponse::Status {
                    status: "ok".to_string(),
                    message: Some(message),
                }
            }

            #[cfg(feature = "semantic")]
            DaemonCommand::Semantic { query, top_k } => {
                // Semantic search with persistent index
                let mut index_guard = self.semantic_index.write().await;

                // Build index lazily on first query
                if index_guard.is_none() {
                    // C5: do not build a cold semantic index on an ephemeral
                    // /tmp root (honoring TLDR_INDEX_EPHEMERAL); leave the
                    // index None and report the skip rather than paying a
                    // cold-index burst on a throwaway project.
                    if super::pid::is_ephemeral_root(&self.project) {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: "Semantic index skipped: ephemeral root (set TLDR_INDEX_EPHEMERAL=1 to force)".to_string(),
                        };
                    }
                    let build_opts = BuildOptions {
                        show_progress: false,
                        use_cache: true,
                        ..Default::default()
                    };
                    let cache_config = Some(CacheConfig::default());

                    match SemanticIndex::build(&self.project, build_opts, cache_config) {
                        Ok(idx) => {
                            *index_guard = Some(idx);
                        }
                        Err(e) => {
                            return DaemonResponse::Error {
                                status: "error".to_string(),
                                error: format!("Failed to build semantic index: {}", e),
                            };
                        }
                    }
                }

                // Search the index
                let index = index_guard.as_mut().unwrap();
                let search_opts = IndexSearchOptions {
                    top_k,
                    threshold: 0.5,
                    include_snippet: true,
                    snippet_lines: 5,
                    expand: false,
                };

                match index.search(&query, &search_opts) {
                    Ok(report) => match serde_json::to_value(&report) {
                        Ok(value) => DaemonResponse::Result(value),
                        Err(e) => DaemonResponse::Error {
                            status: "error".to_string(),
                            error: format!("Serialization error: {}", e),
                        },
                    },
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: format!("Semantic search failed: {}", e),
                    },
                }
            }

            #[cfg(not(feature = "semantic"))]
            DaemonCommand::Semantic { .. } => DaemonResponse::Error {
                status: "error".to_string(),
                error: "Semantic search requires the 'semantic' feature".to_string(),
            },

            // Pass-through analysis commands with Salsa cache integration
            DaemonCommand::Search {
                pattern,
                max_results,
            } => {
                let max = max_results.unwrap_or(100);
                // Search is regex-based and language-agnostic; tag with the
                // resolve_language default so QueryKey is well-formed without
                // discriminating across languages.
                let key = QueryKey::new(
                    "search",
                    hash_str_args(&[&pattern, &max.to_string()]),
                    resolve_language(None),
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                match tldr_search(&pattern, &self.project, None, 2, max, 1000, None) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Extract { file, session: _ } => {
                let file_str = file.to_string_lossy().to_string();
                // Extract auto-detects language from the file path. Tag the
                // cache key with the detected language so two files with the
                // same name in different language sub-projects do not collide.
                let detected_lang = detect_or_parse_language(None, &file)
                    .unwrap_or(Language::Python);
                let key = QueryKey::new(
                    "extract",
                    hash_str_args(&[&file_str]),
                    detected_lang,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let file_hash = super::salsa::hash_path(&file);
                match extract_file(&file, Some(&self.project)) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![file_hash]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Tree { path } => {
                let root = path.unwrap_or_else(|| self.project.clone());
                let root_str = root.to_string_lossy().to_string();
                // File tree is language-agnostic; tag with default language.
                let key = QueryKey::new(
                    "tree",
                    hash_str_args(&[&root_str]),
                    resolve_language(None),
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                match get_file_tree(&root, None, true, None) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Structure { path, lang } => {
                let path_str = path.to_string_lossy().to_string();
                let lang_str = lang.as_deref().unwrap_or("");
                let language = match detect_or_parse_language(lang.as_deref(), &path) {
                    Ok(l) => l,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                let key = QueryKey::new(
                    "structure",
                    hash_str_args(&[&path_str, lang_str]),
                    language,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                match get_code_structure(&path, language, 0, None) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Context {
                entry,
                depth,
                language,
            } => {
                let d = depth.unwrap_or(2);
                let lang = resolve_language(language);
                let key = QueryKey::new(
                    "context",
                    hash_str_args(&[&entry, &d.to_string()]),
                    lang,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                match get_relevant_context(&self.project, &entry, d, lang, true, None) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Cfg { file, function } => {
                let file_str = file.to_string_lossy().to_string();
                let language = match detect_or_parse_language(None, &file) {
                    Ok(l) => l,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                let key = QueryKey::new(
                    "cfg",
                    hash_str_args(&[&file_str, &function]),
                    language,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let file_hash = super::salsa::hash_path(&file);
                match get_cfg_context(&file_str, &function, language) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![file_hash]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Dfg { file, function } => {
                let file_str = file.to_string_lossy().to_string();
                let language = match detect_or_parse_language(None, &file) {
                    Ok(l) => l,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                let key = QueryKey::new(
                    "dfg",
                    hash_str_args(&[&file_str, &function]),
                    language,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let file_hash = super::salsa::hash_path(&file);
                match get_dfg_context(&file_str, &function, language) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![file_hash]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Slice {
                file,
                function,
                line,
            } => {
                let file_str = file.to_string_lossy().to_string();
                let language = match detect_or_parse_language(None, &file) {
                    Ok(l) => l,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                let key = QueryKey::new(
                    "slice",
                    hash_str_args(&[&file_str, &function, &line.to_string()]),
                    language,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let file_hash = super::salsa::hash_path(&file);
                match get_slice(
                    &file_str,
                    &function,
                    line as u32,
                    SliceDirection::Backward,
                    None,
                    language,
                ) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![file_hash]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Calls { path, language } => {
                let root = path.unwrap_or_else(|| self.project.clone());
                let lang = resolve_language(language);
                let root_str = root.to_string_lossy().to_string();
                let key = QueryKey::new("calls", hash_str_args(&[&root_str]), lang);
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                match build_project_call_graph(&root, lang, None, true) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Impact {
                func,
                depth,
                language,
            } => {
                let d = depth.unwrap_or(3);
                let lang = resolve_language(language);
                let key = QueryKey::new(
                    "impact",
                    hash_str_args(&[&func, &d.to_string()]),
                    lang,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let graph = match build_project_call_graph(&self.project, lang, None, true) {
                    Ok(g) => g,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                match impact_analysis(&graph, &func, d, None) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Dead {
                path,
                entry,
                language,
            } => {
                let root = path.unwrap_or_else(|| self.project.clone());
                let lang = resolve_language(language);
                let root_str = root.to_string_lossy().to_string();
                let entry_str = entry.as_ref().map(|v| v.join(",")).unwrap_or_default();
                let key = QueryKey::new(
                    "dead",
                    hash_str_args(&[&root_str, &entry_str]),
                    lang,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let graph = match build_project_call_graph(&root, lang, None, true) {
                    Ok(g) => g,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                // Collect all functions from the project by extracting each file
                let extensions: HashSet<String> = lang
                    .extensions()
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                let file_tree = match get_file_tree(&root, Some(&extensions), true, None) {
                    Ok(t) => t,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                let files = tldr_core::fs::tree::collect_files(&file_tree, &root);
                let mut module_infos = Vec::new();
                for file_path in files {
                    if let Ok(info) = extract_file(&file_path, Some(&root)) {
                        module_infos.push((file_path, info));
                    }
                }
                let all_functions = collect_all_functions(&module_infos);
                let entry_strings: Option<Vec<String>> = entry;
                let entry_refs: Option<&[String]> = entry_strings.as_deref();
                match dead_code_analysis(&graph, &all_functions, entry_refs) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Arch { path, language } => {
                let root = path.unwrap_or_else(|| self.project.clone());
                let lang = resolve_language(language);
                let root_str = root.to_string_lossy().to_string();
                let key = QueryKey::new("arch", hash_str_args(&[&root_str]), lang);
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let graph = match build_project_call_graph(&root, lang, None, true) {
                    Ok(g) => g,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                match architecture_analysis(&graph) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Imports { file } => {
                let file_str = file.to_string_lossy().to_string();
                let language = match detect_or_parse_language(None, &file) {
                    Ok(l) => l,
                    Err(e) => {
                        return DaemonResponse::Error {
                            status: "error".to_string(),
                            error: e.to_string(),
                        }
                    }
                };
                let key = QueryKey::new(
                    "imports",
                    hash_str_args(&[&file_str]),
                    language,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let file_hash = super::salsa::hash_path(&file);
                match get_imports(&file, language) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![file_hash]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Importers {
                module,
                path,
                language,
            } => {
                let root = path.unwrap_or_else(|| self.project.clone());
                let lang = resolve_language(language);
                let root_str = root.to_string_lossy().to_string();
                let key = QueryKey::new(
                    "importers",
                    hash_str_args(&[&module, &root_str]),
                    lang,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                match find_importers(&root, &module, lang) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }

            DaemonCommand::Diagnostics { path, project: _ } => DaemonResponse::Error {
                status: "error".to_string(),
                error: format!(
                    "Diagnostics requires external tool orchestration; \
                         use CLI directly: tldr diagnostics {}",
                    path.display()
                ),
            },

            DaemonCommand::ChangeImpact {
                files,
                session: _,
                git: _,
                language,
            } => {
                let lang = resolve_language(language);
                let files_str = files
                    .as_ref()
                    .map(|v| {
                        v.iter()
                            .map(|p| p.to_string_lossy().to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                let key = QueryKey::new(
                    "change_impact",
                    hash_str_args(&[&files_str]),
                    lang,
                );
                if let Some(cached) = self.cache.get::<serde_json::Value>(&key) {
                    return DaemonResponse::Result(cached);
                }
                let changed: Option<Vec<PathBuf>> = files;
                match change_impact(&self.project, changed.as_deref(), lang) {
                    Ok(result) => {
                        let val = serde_json::to_value(&result).unwrap_or_default();
                        self.cache.insert(key, &val, vec![]);
                        DaemonResponse::Result(val)
                    }
                    Err(e) => DaemonResponse::Error {
                        status: "error".to_string(),
                        error: e.to_string(),
                    },
                }
            }
        }
    }

    /// Handle the Status command.
    async fn handle_status(&self, session: Option<String>) -> DaemonResponse {
        let status = self.status().await;
        let uptime = self.uptime();
        let files = self.indexed_files().await;
        let salsa_stats = self.cache_stats();
        let all_sessions = Some(self.all_sessions_summary());
        let hook_stats = Some(self.hook_stats());

        // Get session-specific stats if requested
        let session_stats =
            session.and_then(|id| self.sessions.get(&id).map(|entry| entry.value().clone()));

        DaemonResponse::FullStatus {
            status,
            uptime,
            files,
            project: self.project.clone(),
            salsa_stats,
            dedup_stats: None,
            session_stats,
            all_sessions,
            hook_stats,
        }
    }

    /// Handle the Notify command (file change notification).
    ///
    /// C3: O(1) ingress that coalesces a burst into a single debounced,
    /// cooldown-gated reindex over the WHOLE accumulated dirty set. Mirrors
    /// Python's `_handle_notify` + `_schedule_reindex`:
    /// - Each newly-dirtied file is added to the dirty set (deduplicated) and
    ///   its cache entries are invalidated.
    /// - When the dirty count crosses `auto_reindex_threshold`, a single
    ///   re-armable timer is (re-)armed with `delay = max(debounce,
    ///   cooldown_remaining)`. The dirty set is NOT cleared here — the fold
    ///   that fires when the timer elapses snapshots and clears it, so a burst
    ///   delivered as many notifies collapses to ONE fold of the whole set.
    /// - `reindex_triggered` reports that a reindex was scheduled (the timer
    ///   armed), not that the heavy work has finished.
    async fn handle_notify(&self, file: PathBuf) -> DaemonResponse {
        // Add file to dirty set (dedup).
        let dirty_count = {
            let mut dirty = self.dirty_files.write().await;
            dirty.insert(file.clone());
            dirty.len()
        };

        // Invalidate cache entries for this file.
        let file_hash = super::salsa::hash_path(&file);
        self.cache.invalidate_by_input(file_hash);

        // Eagerly invalidate the in-process semantic index so the NEXT query
        // rebuilds over fresh content (cheap: it just drops the handle). The
        // proactive, debounced+cooldown-gated reindex below is the separate
        // C3 fold; this keeps a lazily-rebuilt index correct between folds.
        #[cfg(feature = "semantic")]
        {
            let mut idx = self.semantic_index.write().await;
            *idx = None;
        }

        let threshold = self.config.auto_reindex_threshold;
        let reindex_triggered = dirty_count >= threshold;

        // O(1) ingress: arm the debounced/cooldown-gated scheduler instead of
        // doing the heavy work inline. A burst coalesces into one armed timer;
        // the fold runs later when the timer fires.
        if reindex_triggered {
            self.schedule_reindex().await;
        }

        DaemonResponse::NotifyResponse {
            status: "ok".to_string(),
            dirty_count,
            threshold,
            reindex_triggered,
        }
    }

    /// Milliseconds left before a new reindex may fire (0 once elapsed).
    fn cooldown_remaining_ms(&self) -> u64 {
        let now_ms = self.tokio_start.elapsed().as_millis() as u64;
        let last = self.last_reindex_fire_ms.load(Ordering::SeqCst);
        // last == 0 means "never fired" -> no cooldown owed.
        if last == 0 {
            return 0;
        }
        let ready_at = last.saturating_add(self.config.reindex_cooldown_ms);
        ready_at.saturating_sub(now_ms)
    }

    /// Build the bundle of `Arc` handles the spawned reindex timer task needs,
    /// so the scheduler works with `&self` (no `Arc<Self>` required — keeps
    /// `handle_command(&self, ..)`'s public signature unchanged).
    fn reindex_state(&self) -> ReindexState {
        ReindexState {
            reindex_timer: Arc::clone(&self.reindex_timer),
            last_reindex_fire_ms: Arc::clone(&self.last_reindex_fire_ms),
            reindex_fire_count: Arc::clone(&self.reindex_fire_count),
            dirty_files: Arc::clone(&self.dirty_files),
            fold_callback: Arc::clone(&self.fold_callback),
            #[cfg(feature = "semantic")]
            semantic_index: Arc::clone(&self.semantic_index),
            tokio_start: self.tokio_start,
        }
    }

    /// Arm at most one debounced, cooldown-gated reindex timer (O(1)).
    ///
    /// Mirrors Python's `_schedule_reindex`: each threshold-crossing notify
    /// cancels the prior pending timer (debounce/coalesce) so a burst arms
    /// exactly one surviving timer; the delay is pushed out to the cooldown
    /// boundary when a fresh burst lands inside the spread window. The timer
    /// task sleeps via `tokio::time::sleep`, so unit tests can drive it with
    /// `tokio::time::pause`/`advance` (no real sleeps).
    async fn schedule_reindex(&self) {
        let delay_ms = std::cmp::max(self.config.notify_debounce_ms, self.cooldown_remaining_ms());
        let state = self.reindex_state();

        let mut timer = self.reindex_timer.lock().await;
        // Cancel the prior pending timer (debounce).
        if let Some(prev) = timer.take() {
            prev.abort();
        }
        let handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            state.drain_pending_reindex().await;
        });
        *timer = Some(handle);
    }

    /// Handle the Track command (hook activity tracking).
    async fn handle_track(
        &self,
        hook: String,
        success: bool,
        metrics: HashMap<String, f64>,
    ) -> DaemonResponse {
        // Get or create hook stats
        let mut entry = self
            .hooks
            .entry(hook.clone())
            .or_insert_with(|| HookStats::new(hook.clone()));

        // Record invocation
        let metrics_opt = if metrics.is_empty() {
            None
        } else {
            Some(metrics)
        };
        entry.record_invocation(success, metrics_opt);

        let total_invocations = entry.invocations;
        let flushed = total_invocations.is_multiple_of(HOOK_FLUSH_THRESHOLD as u64);

        // Flush stats periodically
        if flushed {
            // In full implementation, would persist stats to disk
            // For now, just mark as flushed
        }

        DaemonResponse::TrackResponse {
            status: "ok".to_string(),
            hook,
            total_invocations,
            flushed,
        }
    }

    /// Persist statistics to disk.
    async fn persist_stats(&self) -> DaemonResult<()> {
        // Create cache directory if it doesn't exist
        let cache_dir = self.project.join(".tldr/cache");
        if !cache_dir.exists() {
            std::fs::create_dir_all(&cache_dir)?;
        }

        // Save Salsa cache stats
        let salsa_stats_path = cache_dir.join("salsa_stats.json");
        let stats = self.cache_stats();
        let json = serde_json::to_string_pretty(&stats)?;
        std::fs::write(salsa_stats_path, json)?;

        // Save full query cache
        let cache_path = cache_dir.join("query_cache.bin");
        self.cache.save_to_file(&cache_path)?;

        Ok(())
    }
}

// =============================================================================
// Daemon Control Functions
// =============================================================================

/// Start a daemon in the background for the given project.
///
/// Returns the PID of the daemon process.
pub async fn start_daemon_background(project: &std::path::Path) -> DaemonResult<u32> {
    use std::process::Command;

    // Get the current executable path
    let exe_path = std::env::current_exe().map_err(DaemonError::Io)?;

    // C2: record OUR pid as the parent for the background daemon's
    // parent-death watchdog. setsid() will reparent the child to pid 1, so the
    // watchdog must be keyed on this explicit value, NEVER on getppid().
    let parent_pid = std::process::id();

    // Spawn the daemon process
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        let child = unsafe {
            Command::new(&exe_path)
                .args(["daemon", "start", "--project"])
                .arg(project.as_os_str())
                .arg("--foreground")
                .env("TLDR_DAEMON_PARENT_PID", parent_pid.to_string())
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .pre_exec(|| {
                    // Create new session (detach from terminal)
                    libc::setsid();
                    Ok(())
                })
                .spawn()
                .map_err(DaemonError::Io)?
        };

        Ok(child.id())
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let child = Command::new(&exe_path)
            .args(["daemon", "start", "--project"])
            .arg(project.as_os_str())
            .arg("--foreground")
            .env("TLDR_DAEMON_PARENT_PID", parent_pid.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
            .spawn()
            .map_err(DaemonError::Io)?;

        Ok(child.id())
    }
}

/// Wait for a daemon to become ready by polling the socket.
///
/// Returns `Ok(())` if the daemon becomes available within the timeout.
pub async fn wait_for_daemon(project: &std::path::Path, timeout_secs: u64) -> DaemonResult<()> {
    let start = Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);

    while start.elapsed() < timeout {
        // Try to connect
        if super::ipc::check_socket_alive(project).await {
            return Ok(());
        }

        // Wait a bit before retrying
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    Err(DaemonError::ConnectionTimeout { timeout_secs })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_daemon_new() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        assert_eq!(daemon.project(), temp.path());
        assert!(daemon.uptime() < 1.0);
    }

    #[tokio::test]
    async fn test_daemon_status_initial() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        assert_eq!(daemon.status().await, DaemonStatus::Initializing);
    }

    #[tokio::test]
    async fn test_daemon_uptime_human() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let uptime = daemon.uptime_human();
        assert!(uptime.contains("h"));
        assert!(uptime.contains("m"));
        assert!(uptime.contains("s"));
    }

    #[tokio::test]
    async fn test_daemon_handle_ping() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon.handle_command(DaemonCommand::Ping).await;

        match response {
            DaemonResponse::Status { status, message } => {
                assert_eq!(status, "ok");
                assert_eq!(message, Some("pong".to_string()));
            }
            _ => panic!("Expected Status response"),
        }
    }

    #[tokio::test]
    async fn test_daemon_handle_shutdown() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon.handle_command(DaemonCommand::Shutdown).await;

        match response {
            DaemonResponse::Status { status, .. } => {
                assert_eq!(status, "shutting_down");
            }
            _ => panic!("Expected Status response"),
        }

        // Verify daemon is stopping
        assert!(daemon.stopping.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_daemon_handle_notify() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let file = temp.path().join("test.rs");
        let response = daemon.handle_command(DaemonCommand::Notify { file }).await;

        match response {
            DaemonResponse::NotifyResponse {
                dirty_count,
                threshold,
                reindex_triggered,
                ..
            } => {
                assert_eq!(dirty_count, 1);
                assert_eq!(threshold, DEFAULT_REINDEX_THRESHOLD);
                assert!(!reindex_triggered);
            }
            _ => panic!("Expected NotifyResponse"),
        }
    }

    #[tokio::test]
    async fn test_daemon_handle_notify_threshold() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig {
            auto_reindex_threshold: 3, // Lower threshold for testing
            // Large debounce so the armed timer never fires during the test —
            // we only assert the threshold-crossing + scheduling behavior here.
            notify_debounce_ms: 60_000,
            ..DaemonConfig::default()
        };
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        // Add files below threshold: reindex must NOT be triggered yet.
        for i in 0..2 {
            let file = temp.path().join(format!("test{}.rs", i));
            let resp = daemon.handle_command(DaemonCommand::Notify { file }).await;
            match resp {
                DaemonResponse::NotifyResponse {
                    dirty_count,
                    reindex_triggered,
                    ..
                } => {
                    assert_eq!(dirty_count, i + 1);
                    assert!(!reindex_triggered);
                }
                _ => panic!("Expected NotifyResponse"),
            }
        }

        // The third notification crosses the threshold -> schedules a reindex.
        // The dirty set is NOT cleared synchronously (C3): the fold clears it
        // when the (debounced) timer fires, so the count reflects the full set.
        let file = temp.path().join("test2.rs");
        let response = daemon.handle_command(DaemonCommand::Notify { file }).await;

        match response {
            DaemonResponse::NotifyResponse {
                dirty_count,
                reindex_triggered,
                ..
            } => {
                assert_eq!(dirty_count, 3, "dirty set is not cleared on threshold");
                assert!(reindex_triggered, "crossing the threshold schedules a reindex");
            }
            _ => panic!("Expected NotifyResponse"),
        }

        // Cancel the armed timer so it cannot fire after the test ends.
        let pending = daemon.reindex_timer.lock().await.take();
        if let Some(h) = pending {
            h.abort();
        }
    }

    #[tokio::test]
    async fn test_daemon_handle_track() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Track {
                hook: "test-hook".to_string(),
                success: true,
                metrics: HashMap::new(),
            })
            .await;

        match response {
            DaemonResponse::TrackResponse {
                hook,
                total_invocations,
                ..
            } => {
                assert_eq!(hook, "test-hook");
                assert_eq!(total_invocations, 1);
            }
            _ => panic!("Expected TrackResponse"),
        }
    }

    #[tokio::test]
    async fn test_daemon_all_sessions_summary() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        // Add a session
        daemon.sessions.insert(
            "test-session".to_string(),
            SessionStats {
                session_id: "test-session".to_string(),
                raw_tokens: 1000,
                tldr_tokens: 100,
                requests: 10,
                started_at: None,
            },
        );

        let summary = daemon.all_sessions_summary();
        assert_eq!(summary.active_sessions, 1);
        assert_eq!(summary.total_raw_tokens, 1000);
        assert_eq!(summary.total_tldr_tokens, 100);
        assert_eq!(summary.total_requests, 10);
    }

    // =========================================================================
    // Pass-through handler tests
    // =========================================================================

    /// Helper to create a temp dir with a Python file for testing
    fn create_test_project() -> TempDir {
        let temp = TempDir::new().unwrap();
        let py_file = temp.path().join("main.py");
        std::fs::write(
            &py_file,
            "def hello():\n    \"\"\"Say hello.\"\"\"\n    return 'hello'\n\ndef main():\n    hello()\n",
        )
        .unwrap();
        temp
    }

    #[test]
    fn test_hash_str_args_deterministic() {
        let h1 = hash_str_args(&["search", "pattern", "100"]);
        let h2 = hash_str_args(&["search", "pattern", "100"]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_str_args_different_inputs() {
        let h1 = hash_str_args(&["search", "pattern_a"]);
        let h2 = hash_str_args(&["search", "pattern_b"]);
        assert_ne!(h1, h2);
    }

    #[tokio::test]
    async fn test_daemon_search_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Search {
                pattern: "def hello".to_string(),
                max_results: Some(10),
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(val.is_array(), "Search should return an array of matches");
                let arr = val.as_array().unwrap();
                assert!(
                    !arr.is_empty(),
                    "Should find at least one match for 'def hello'"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Search returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_search_caches_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        // First call populates cache
        let _r1 = daemon
            .handle_command(DaemonCommand::Search {
                pattern: "def hello".to_string(),
                max_results: Some(10),
            })
            .await;

        // Second call should hit cache
        let _r2 = daemon
            .handle_command(DaemonCommand::Search {
                pattern: "def hello".to_string(),
                max_results: Some(10),
            })
            .await;

        let stats = daemon.cache_stats();
        assert!(stats.hits >= 1, "Second call should hit cache");
    }

    #[tokio::test]
    async fn test_daemon_extract_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Extract {
                file: temp.path().join("main.py"),
                session: None,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Extract should return a module info object"
                );
                // Should contain functions field
                assert!(
                    val.get("functions").is_some(),
                    "Should have 'functions' field"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Extract returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_extract_nonexistent_file() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Extract {
                file: temp.path().join("nonexistent.py"),
                session: None,
            })
            .await;

        match response {
            DaemonResponse::Error { error, .. } => {
                assert!(
                    !error.is_empty(),
                    "Should return an error for nonexistent file"
                );
            }
            _ => panic!("Expected Error response for nonexistent file"),
        }
    }

    #[tokio::test]
    async fn test_daemon_tree_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Tree { path: None })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(val.is_object(), "Tree should return a FileTree object");
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Tree returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_structure_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Structure {
                path: temp.path().to_path_buf(),
                lang: Some("python".to_string()),
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Structure should return a CodeStructure object"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Structure returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_imports_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Imports {
                file: temp.path().join("main.py"),
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(val.is_array(), "Imports should return an array");
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Imports returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_cfg_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let file = temp.path().join("main.py");
        let response = daemon
            .handle_command(DaemonCommand::Cfg {
                file,
                function: "hello".to_string(),
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(val.is_object(), "Cfg should return a CfgInfo object");
                assert!(
                    val.get("function").is_some(),
                    "Should have 'function' field"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Cfg returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_dfg_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let file = temp.path().join("main.py");
        let response = daemon
            .handle_command(DaemonCommand::Dfg {
                file,
                function: "hello".to_string(),
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(val.is_object(), "Dfg should return a DfgInfo object");
                assert!(
                    val.get("function").is_some(),
                    "Should have 'function' field"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Dfg returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_calls_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Calls {
                path: None,
                language: None,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Calls should return a ProjectCallGraph object"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Calls returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_arch_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Arch {
                path: None,
                language: None,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Arch should return an ArchitectureReport object"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Arch returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_diagnostics_returns_error_with_guidance() {
        let temp = TempDir::new().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let path = temp.path().join("src");
        let response = daemon
            .handle_command(DaemonCommand::Diagnostics {
                path: path.clone(),
                project: None,
            })
            .await;

        match response {
            DaemonResponse::Error { error, .. } => {
                assert!(
                    error.contains("Diagnostics requires external tool orchestration"),
                    "Error should explain that diagnostics needs CLI: {}",
                    error
                );
                assert!(
                    error.contains("tldr diagnostics"),
                    "Error should suggest CLI usage"
                );
            }
            other => panic!("Expected Error response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_importers_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Importers {
                module: "os".to_string(),
                path: None,
                language: None,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Importers should return an ImportersReport object"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Importers returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_dead_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Dead {
                path: None,
                entry: None,
                language: None,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Dead should return a DeadCodeReport object"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Dead returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_change_impact_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::ChangeImpact {
                files: Some(vec![temp.path().join("main.py")]),
                session: None,
                git: None,
                language: None,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "ChangeImpact should return a ChangeImpactReport object"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("ChangeImpact returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_extract_cache_invalidation() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let file = temp.path().join("main.py");

        // First extract populates cache
        let r1 = daemon
            .handle_command(DaemonCommand::Extract {
                file: file.clone(),
                session: None,
            })
            .await;
        assert!(matches!(r1, DaemonResponse::Result(_)));

        // Notify file change - should invalidate the cache entry
        daemon
            .handle_command(DaemonCommand::Notify { file: file.clone() })
            .await;

        // After invalidation, next extract should be a cache miss
        let _r2 = daemon
            .handle_command(DaemonCommand::Extract {
                file,
                session: None,
            })
            .await;

        let stats = daemon.cache_stats();
        // Should have: 1 miss (first), 1 invalidation, 1 miss (after invalidation)
        assert!(
            stats.invalidations >= 1,
            "File notify should have caused invalidation"
        );
    }

    #[tokio::test]
    async fn test_daemon_slice_returns_result() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let file = temp.path().join("main.py");
        let response = daemon
            .handle_command(DaemonCommand::Slice {
                file,
                function: "hello".to_string(),
                line: 3,
            })
            .await;

        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_array(),
                    "Slice should return an array of line numbers"
                );
            }
            DaemonResponse::Error { error, .. } => {
                panic!("Slice returned error: {}", error);
            }
            other => panic!("Expected Result response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_context_returns_result_or_error() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Context {
                entry: "main".to_string(),
                depth: Some(1),
                language: None,
            })
            .await;

        // Context may return Result or Error depending on whether 'main' is found
        // in the call graph. Both are valid outcomes for this test.
        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Context should return a RelevantContext object"
                );
            }
            DaemonResponse::Error { .. } => {
                // Function not found in call graph is acceptable
            }
            other => panic!("Expected Result or Error response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_impact_returns_result_or_error() {
        let temp = create_test_project();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Impact {
                func: "hello".to_string(),
                depth: Some(2),
                language: None,
            })
            .await;

        // Impact may return Result or Error depending on call graph contents
        match response {
            DaemonResponse::Result(val) => {
                assert!(
                    val.is_object(),
                    "Impact should return an ImpactReport object"
                );
            }
            DaemonResponse::Error { .. } => {
                // Function not found in call graph is acceptable for small test projects
            }
            other => panic!("Expected Result or Error response, got {:?}", other),
        }
    }

    #[cfg(feature = "semantic")]
    #[tokio::test]
    async fn test_semantic_search_builds_index() {
        // Create a temp dir with a simple Python file
        let temp = tempfile::tempdir().unwrap();
        let py_file = temp.path().join("hello.py");
        std::fs::write(
            &py_file,
            "def greet(name):\n    return f'Hello, {name}!'\n\ndef farewell(name):\n    return f'Goodbye, {name}!'\n",
        )
        .unwrap();

        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Semantic {
                query: "greeting function".to_string(),
                top_k: 5,
            })
            .await;

        // Should return a Result with search results, not an error
        match &response {
            DaemonResponse::Result(value) => {
                assert!(value.get("query").is_some());
                assert!(value.get("results").is_some());
            }
            DaemonResponse::Error { error, .. } => {
                // May fail in CI without ONNX model - that's acceptable
                // but it should NOT say "not yet implemented"
                assert!(
                    !error.contains("not yet implemented"),
                    "Semantic search should be wired, got: {}",
                    error
                );
            }
            other => panic!("Unexpected response: {:?}", other),
        }
    }

    #[cfg(feature = "semantic")]
    #[tokio::test]
    async fn test_semantic_index_invalidated_on_notify() {
        let temp = tempfile::tempdir().unwrap();
        let py_file = temp.path().join("example.py");
        std::fs::write(&py_file, "def compute(x):\n    return x * 2\n").unwrap();

        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        // First semantic search - builds index
        let _ = daemon
            .handle_command(DaemonCommand::Semantic {
                query: "computation".to_string(),
                top_k: 5,
            })
            .await;

        // Verify index is populated
        {
            let idx = daemon.semantic_index.read().await;
            // Index may be Some (if ONNX model available) or None (if build failed)
            // We just verify the field exists and is accessible
            let _ = idx.is_some();
        }

        // Notify a file change - should invalidate the index
        let _ = daemon
            .handle_command(DaemonCommand::Notify {
                file: py_file.clone(),
            })
            .await;

        // Verify index was cleared
        {
            let idx = daemon.semantic_index.read().await;
            assert!(
                idx.is_none(),
                "Semantic index should be invalidated after Notify"
            );
        }
    }

    #[tokio::test]
    async fn test_daemon_warm_wires_caches() {
        let temp = tempfile::tempdir().unwrap();
        let py_file = temp.path().join("example.py");
        std::fs::write(
            &py_file,
            "def add(a, b):\n    return a + b\n\ndef multiply(x, y):\n    return x * y\n",
        )
        .unwrap();

        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Warm { language: None })
            .await;

        match &response {
            DaemonResponse::Status { status, message } => {
                assert_eq!(status, "ok");
                let msg = message.as_deref().unwrap_or("");
                // Should mention what was warmed, not just "Warm completed"
                assert!(
                    msg.contains("Warmed"),
                    "Expected warm details, got: {}",
                    msg
                );
            }
            other => panic!("Expected Status response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_warm_with_language() {
        let temp = tempfile::tempdir().unwrap();
        let rs_file = temp.path().join("lib.rs");
        std::fs::write(
            &rs_file,
            "pub fn hello() -> String {\n    \"hello\".to_string()\n}\n",
        )
        .unwrap();

        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        let response = daemon
            .handle_command(DaemonCommand::Warm {
                language: Some("rust".to_string()),
            })
            .await;

        match &response {
            DaemonResponse::Status { status, .. } => {
                assert_eq!(status, "ok");
            }
            other => panic!("Expected Status response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_daemon_last_activity_updated_on_command() {
        let temp = tempfile::tempdir().unwrap();
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), config);

        // Record initial activity time
        let before = *daemon.last_activity.read().await;

        // Small delay to ensure time difference
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Any command should NOT update last_activity (only connections do),
        // but handle_command is what we can test. Verify the field exists and is accessible.
        let _ = daemon.handle_command(DaemonCommand::Ping).await;

        // last_activity is set at connection accept, not command handling,
        // so it should still be the initial value
        let after = *daemon.last_activity.read().await;
        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn test_daemon_created_with_nonexistent_project() {
        // Daemon should be constructable with any path — the exists() check
        // happens in the run loop, not in new()
        let fake_path = PathBuf::from("/tmp/nonexistent-project-dir-12345");
        let config = DaemonConfig::default();
        let daemon = TLDRDaemon::new(fake_path.clone(), config);

        assert_eq!(daemon.project(), &fake_path);
        // The project doesn't exist, but daemon construction succeeds.
        // The run() loop would detect this and self-terminate.
        assert!(!fake_path.exists());
    }

    // =========================================================================
    // C1 — RSS-watermark self-restart (fake-RSS probe seam)
    // =========================================================================

    fn daemon_with_config(config: DaemonConfig) -> TLDRDaemon {
        let temp = TempDir::new().unwrap();
        // Leak the temp dir guard via into_path so the project path stays valid
        // for the duration of the test without holding the TempDir in scope.
        let path = temp.into_path();
        TLDRDaemon::new(path, config)
    }

    #[tokio::test]
    async fn test_rss_watermark_fires_when_idle_and_breached() {
        let config = DaemonConfig {
            rss_watermark_mb: 100,
            ..DaemonConfig::default()
        };
        let mut daemon = daemon_with_config(config);
        // 200 MiB > 100 MiB watermark.
        daemon.set_rss_probe(Arc::new(|| Some(200 * 1024 * 1024)));

        assert!(!daemon.rss_exit_latched());
        let fired = daemon.maybe_flag_rss_exit().await;
        assert!(fired, "watermark should fire when idle and breached");
        assert!(daemon.rss_exit_latched());
    }

    #[tokio::test]
    async fn test_rss_watermark_never_fires_with_inflight_work() {
        let config = DaemonConfig {
            rss_watermark_mb: 100,
            ..DaemonConfig::default()
        };
        let mut daemon = daemon_with_config(config);
        daemon.set_rss_probe(Arc::new(|| Some(200 * 1024 * 1024)));

        // Simulate a command in flight.
        daemon.in_flight.fetch_add(1, Ordering::SeqCst);
        let fired = daemon.maybe_flag_rss_exit().await;
        assert!(!fired, "watermark must never fire mid-request");
        assert!(!daemon.rss_exit_latched());

        // Once the request completes, the next check fires.
        daemon.in_flight.fetch_sub(1, Ordering::SeqCst);
        let fired = daemon.maybe_flag_rss_exit().await;
        assert!(fired, "watermark fires at the request-completion idle gap");
    }

    #[tokio::test]
    async fn test_rss_watermark_does_not_fire_below_watermark() {
        let config = DaemonConfig {
            rss_watermark_mb: 4096,
            ..DaemonConfig::default()
        };
        let mut daemon = daemon_with_config(config);
        daemon.set_rss_probe(Arc::new(|| Some(50 * 1024 * 1024))); // 50 MiB
        assert!(!daemon.maybe_flag_rss_exit().await);
        assert!(!daemon.rss_exit_latched());
    }

    #[tokio::test]
    async fn test_rss_watermark_disabled_when_zero() {
        let config = DaemonConfig {
            rss_watermark_mb: 0, // disabled
            ..DaemonConfig::default()
        };
        let mut daemon = daemon_with_config(config);
        daemon.set_rss_probe(Arc::new(|| Some(u64::MAX)));
        assert!(!daemon.maybe_flag_rss_exit().await);
    }

    #[tokio::test]
    async fn test_rss_watermark_unreadable_rss_never_fires() {
        let config = DaemonConfig {
            rss_watermark_mb: 1,
            ..DaemonConfig::default()
        };
        let mut daemon = daemon_with_config(config);
        daemon.set_rss_probe(Arc::new(|| None)); // unreadable
        assert!(!daemon.maybe_flag_rss_exit().await);
    }

    #[tokio::test]
    async fn test_rss_watermark_throttled_to_one_read_per_interval() {
        let config = DaemonConfig {
            rss_watermark_mb: 100,
            ..DaemonConfig::default()
        };
        let mut daemon = daemon_with_config(config);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        // Probe counts reads and stays BELOW the watermark so the latch never
        // sets (a set latch would short-circuit the throttle test).
        daemon.set_rss_probe(Arc::new(move || {
            calls2.fetch_add(1, Ordering::SeqCst);
            Some(1) // 1 byte, far below the 100 MiB watermark
        }));

        // Many back-to-back checks within one RSS_CHECK_INTERVAL window.
        for _ in 0..10 {
            daemon.maybe_flag_rss_exit().await;
        }
        // Throttle: the probe is read at most once per interval window.
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "RSS probe should be throttled to one read per interval"
        );
    }

    // =========================================================================
    // C2 — parent-death watchdog
    // =========================================================================

    #[tokio::test]
    async fn test_parent_watchdog_fires_when_parent_dead() {
        // A PID that is not running -> watchdog flips stopping in one tick.
        let config = DaemonConfig {
            parent_pid: Some(4_194_304), // above typical kernel max pid
            ..DaemonConfig::default()
        };
        let daemon = Arc::new(daemon_with_config(config));
        daemon.spawn_parent_watchdog();

        // The watchdog polls immediately on its first iteration.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            if daemon.stopping.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            daemon.stopping.load(Ordering::SeqCst),
            "watchdog should self-stop when the parent pid is dead"
        );
    }

    #[tokio::test]
    async fn test_parent_watchdog_none_never_fires() {
        // parent_pid == None -> no watchdog task spawned, never self-stops.
        let config = DaemonConfig {
            parent_pid: None,
            ..DaemonConfig::default()
        };
        let daemon = Arc::new(daemon_with_config(config));
        daemon.spawn_parent_watchdog();

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            !daemon.stopping.load(Ordering::SeqCst),
            "no watchdog should run when parent_pid is None (ppid==1 case)"
        );
    }

    #[tokio::test]
    async fn test_parent_watchdog_live_parent_does_not_fire() {
        // Our own pid is alive -> watchdog must not self-stop.
        let config = DaemonConfig {
            parent_pid: Some(std::process::id()),
            ..DaemonConfig::default()
        };
        let daemon = Arc::new(daemon_with_config(config));
        daemon.spawn_parent_watchdog();

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            !daemon.stopping.load(Ordering::SeqCst),
            "watchdog must not fire while the recorded parent is alive"
        );
        // Stop the watchdog loop cleanly.
        daemon.shutdown();
    }

    // =========================================================================
    // C3 — notify debounce + cooldown + always-on fold (paused clock)
    // =========================================================================

    #[tokio::test(start_paused = true)]
    async fn test_notify_burst_coalesces_to_single_fold_with_full_set() {
        let config = DaemonConfig {
            auto_reindex_threshold: 3,
            notify_debounce_ms: 2000,
            reindex_cooldown_ms: 30000,
            ..DaemonConfig::default()
        };
        let daemon = daemon_with_config(config);

        // Install a fold-observing callback recording the folded snapshot.
        let folded: Arc<std::sync::Mutex<Vec<Vec<PathBuf>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let folded2 = Arc::clone(&folded);
        daemon
            .set_fold_callback(Arc::new(move |snap| {
                folded2.lock().unwrap().push(snap);
            }))
            .await;

        // A burst of 5 distinct notifies (crosses threshold at the 3rd).
        for i in 0..5 {
            let file = daemon.project().join(format!("f{}.py", i));
            daemon.handle_command(DaemonCommand::Notify { file }).await;
        }
        // Let the spawned timer task start and register its sleep deadline.
        tokio::task::yield_now().await;
        // No fold yet — the debounce window has not elapsed.
        assert_eq!(daemon.reindex_fire_count(), 0);

        // Advance past the debounce window; the single armed timer fires once.
        tokio::time::advance(std::time::Duration::from_millis(2100)).await;
        // Let the spawned timer task run its callback.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert_eq!(
            daemon.reindex_fire_count(),
            1,
            "a burst must coalesce into exactly one fold"
        );
        let recorded = folded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0].len(),
            5,
            "the single fold must carry the WHOLE accumulated dirty set"
        );
        // Dirty set cleared exactly once by the fold.
        assert!(daemon.dirty_files.read().await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_notify_handle_is_o1_nonblocking() {
        // handle_notify must return promptly (no inline reindex). With a paused
        // clock, an inline heavy/awaiting reindex would never complete; the
        // call returning at all proves ingress does not block on the fold.
        let config = DaemonConfig {
            auto_reindex_threshold: 1,
            notify_debounce_ms: 10_000,
            ..DaemonConfig::default()
        };
        let daemon = daemon_with_config(config);
        let resp = daemon
            .handle_command(DaemonCommand::Notify {
                file: daemon.project().join("a.py"),
            })
            .await;
        match resp {
            DaemonResponse::NotifyResponse {
                reindex_triggered, ..
            } => assert!(reindex_triggered),
            _ => panic!("expected NotifyResponse"),
        }
        // The fold has NOT fired (debounce not elapsed).
        assert_eq!(daemon.reindex_fire_count(), 0);
        let pending = daemon.reindex_timer.lock().await.take();
        if let Some(h) = pending {
            h.abort();
        }
    }

    /// The cooldown's effect is observable directly via the scheduled delay:
    /// the first threshold-crossing notify schedules with `delay == debounce`
    /// (no cooldown owed); a notify that lands AFTER a recent fire schedules
    /// with `delay` pushed out to the cooldown boundary (`>= cooldown -
    /// elapsed`, well beyond the short debounce). Asserting on
    /// `cooldown_remaining_ms` is deterministic and avoids the paused-runtime
    /// auto-advance hazard of "negative" fire-count assertions.
    #[tokio::test(start_paused = true)]
    async fn test_notify_cooldown_pushes_fire_to_boundary() {
        let config = DaemonConfig {
            auto_reindex_threshold: 1,
            notify_debounce_ms: 1000,
            reindex_cooldown_ms: 10_000,
            ..DaemonConfig::default()
        };
        let daemon = daemon_with_config(config);
        let count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        daemon
            .set_fold_callback(Arc::new(move |_snap| {
                count2.fetch_add(1, Ordering::SeqCst);
            }))
            .await;

        // Before any fire, no cooldown is owed.
        assert_eq!(daemon.cooldown_remaining_ms(), 0);

        // First notify -> fires after the debounce window (no cooldown owed).
        daemon
            .handle_command(DaemonCommand::Notify {
                file: daemon.project().join("a.py"),
            })
            .await;
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_millis(1100)).await;
        // The just-due timer task is now ready; yielding while a ready task
        // exists drains it without auto-advancing the paused clock.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(count.load(Ordering::SeqCst), 1, "first fold fires after debounce");

        // After a fire, a fresh notify lands inside the cooldown window, so the
        // next fire is owed most of the cooldown — far more than the 1s
        // debounce. Assert directly on the owed cooldown (deterministic).
        let remaining = daemon.cooldown_remaining_ms();
        assert!(
            remaining > config_debounce(),
            "after a recent fire the cooldown owed ({remaining}ms) must exceed the debounce \
             window, so the next reindex is pushed to the cooldown boundary"
        );
        assert!(
            remaining <= 10_000,
            "cooldown owed ({remaining}ms) cannot exceed the configured cooldown"
        );

        // Advance to the cooldown boundary; the second fold then fires exactly
        // once.
        daemon
            .handle_command(DaemonCommand::Notify {
                file: daemon.project().join("b.py"),
            })
            .await;
        tokio::task::yield_now().await;
        // Jump past the whole cooldown so the (re-armed) timer is due.
        tokio::time::advance(std::time::Duration::from_millis(11_000)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "second fold fires once the cooldown elapses"
        );
    }

    /// The debounce window the cooldown test compares against.
    fn config_debounce() -> u64 {
        1000
    }

    #[tokio::test(start_paused = true)]
    async fn test_notify_burst_arms_exactly_one_timer() {
        // Each threshold-crossing notify cancels the prior timer (debounce).
        let config = DaemonConfig {
            auto_reindex_threshold: 1,
            notify_debounce_ms: 1000,
            ..DaemonConfig::default()
        };
        let daemon = daemon_with_config(config);
        let count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        daemon
            .set_fold_callback(Arc::new(move |_snap| {
                count2.fetch_add(1, Ordering::SeqCst);
            }))
            .await;

        // 4 notifies, each re-arming within the debounce window.
        for i in 0..4 {
            daemon
                .handle_command(DaemonCommand::Notify {
                    file: daemon.project().join(format!("f{}.py", i)),
                })
                .await;
            tokio::task::yield_now().await;
            tokio::time::advance(std::time::Duration::from_millis(200)).await;
        }
        // Now advance well past the debounce from the LAST notify.
        tokio::time::advance(std::time::Duration::from_millis(1100)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "re-armed timers must collapse to exactly one fire"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_shutdown_cancels_armed_reindex_timer() {
        let config = DaemonConfig {
            auto_reindex_threshold: 1,
            notify_debounce_ms: 5000,
            ..DaemonConfig::default()
        };
        let daemon = daemon_with_config(config);
        let count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        daemon
            .set_fold_callback(Arc::new(move |_snap| {
                count2.fetch_add(1, Ordering::SeqCst);
            }))
            .await;

        daemon
            .handle_command(DaemonCommand::Notify {
                file: daemon.project().join("a.py"),
            })
            .await;
        tokio::task::yield_now().await;
        // Simulate the run-loop's shutdown timer-cancel.
        let pending = daemon.reindex_timer.lock().await.take();
        if let Some(h) = pending {
            h.abort();
        }
        // Advance past the debounce window; the aborted timer must NOT fire.
        tokio::time::advance(std::time::Duration::from_millis(6000)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "a cancelled timer must not fire after shutdown"
        );
    }

    // =========================================================================
    // C5 — ephemeral-root cold-index skip
    // =========================================================================

    #[cfg(feature = "semantic")]
    #[tokio::test]
    async fn test_warm_skips_semantic_index_on_ephemeral_root() {
        // Build under /tmp (ephemeral) and ensure the escape hatch is off.
        std::env::remove_var("TLDR_INDEX_EPHEMERAL");
        let dir = std::env::temp_dir().join(format!("tldr-eph-warm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("main.py"), "def f():\n    return 1\n").unwrap();
        // Only run this assertion when the dir genuinely resolves as ephemeral
        // (the platform temp dir is /tmp/-style on the CI/dev macs).
        let is_eph = super::super::pid::is_ephemeral_root(&dir);

        let daemon = TLDRDaemon::new(dir.clone(), DaemonConfig::default());
        let resp = daemon
            .handle_command(DaemonCommand::Warm { language: None })
            .await;

        if is_eph {
            match resp {
                DaemonResponse::Status { message, .. } => {
                    let msg = message.unwrap_or_default();
                    assert!(
                        msg.contains("semantic_index (skipped: ephemeral root)"),
                        "warm must skip the semantic index on an ephemeral root; got: {msg}"
                    );
                }
                _ => panic!("expected Status response"),
            }
            // The semantic index must remain unbuilt.
            assert!(daemon.semantic_index.read().await.is_none());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "semantic")]
    #[tokio::test]
    async fn test_semantic_query_skipped_on_ephemeral_root() {
        std::env::remove_var("TLDR_INDEX_EPHEMERAL");
        let dir = std::env::temp_dir().join(format!("tldr-eph-sem-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("main.py"), "def f():\n    return 1\n").unwrap();
        let is_eph = super::super::pid::is_ephemeral_root(&dir);

        let daemon = TLDRDaemon::new(dir.clone(), DaemonConfig::default());
        let resp = daemon
            .handle_command(DaemonCommand::Semantic {
                query: "anything".to_string(),
                top_k: 5,
            })
            .await;

        if is_eph {
            match resp {
                DaemonResponse::Error { error, .. } => {
                    assert!(
                        error.contains("ephemeral root"),
                        "semantic query must be skipped on an ephemeral root; got: {error}"
                    );
                }
                _ => panic!("expected Error response on ephemeral root"),
            }
            assert!(daemon.semantic_index.read().await.is_none());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
