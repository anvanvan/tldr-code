//! context-batch-v1 (area 4): end-to-end CLI tests for the variadic
//! `tldr context` command.
//!
//! Oracle = Python `tldr context` (verified on the polyglot fixture):
//! - single hit → stdout, exit 0;
//! - single miss → `Did you mean` on stderr, non-zero exit;
//! - batch (N symbols) → one block per resolved symbol on stdout,
//!   blank-line-separated; per-symbol misses on stderr; exit 0 if ≥1 resolved,
//!   non-zero if ALL miss;
//! - `--lang all` accepted; `--depth` default 2; qualified `Class.method`;
//!   clap rejects zero entries.

use std::fs;
use std::process::Command as StdCommand;

use assert_cmd::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Create a git-initialised polyglot project (Python `calc.py` + Rust
/// `lib.rs`). A `.git` marker keeps `_find_project_root`-style resolution
/// stable and avoids any stray `/private/tmp/.tldr` hijack.
fn polyglot_repo() -> TempDir {
    // Defensive: a stray marker under /private/tmp corrupts /tmp indexing.
    let _ = fs::remove_dir_all("/private/tmp/.tldr");
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    fs::write(
        p.join("calc.py"),
        r#"def helper(x):
    return x + 1

def compute(x):
    return helper(x) * 2

class Calculator:
    def add(self, a, b):
        return compute(a) + compute(b)
"#,
    )
    .unwrap();
    fs::write(
        p.join("lib.rs"),
        r#"fn helper_rs(x: i32) -> i32 {
    x + 1
}

fn compute_rs(x: i32) -> i32 {
    helper_rs(x) * 2
}

struct Engine;

impl Engine {
    fn run(&self) -> i32 {
        compute_rs(5)
    }
}
"#,
    )
    .unwrap();
    // git init so the project root is unambiguous.
    let _ = StdCommand::new("git").arg("init").arg("-q").current_dir(p).status();
    dir
}

fn count_context_headers(stdout: &str) -> usize {
    // The text format renders each resolved symbol as a `# Code Context:` header.
    stdout.matches("# Code Context:").count()
}

#[test]
fn single_hit_to_stdout_exit_zero() {
    let repo = polyglot_repo();
    tldr_cmd()
        .args(["context", "compute", "-f", "text"])
        .current_dir(repo.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("# Code Context: compute"));
}

#[test]
fn single_miss_did_you_mean_on_stderr_nonzero_exit() {
    let repo = polyglot_repo();
    // `computee` is a near-miss of `compute`.
    let out = tldr_cmd()
        .args(["context", "computee", "-f", "text"])
        .current_dir(repo.path())
        .output()
        .expect("spawn tldr");
    assert!(!out.status.success(), "single miss must exit non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Did you mean"),
        "expected `Did you mean` on stderr, got: {stderr}"
    );
    assert!(stderr.contains("compute"), "expected `compute` suggestion: {stderr}");
}

#[test]
fn fuzzy_suggestion_for_non_substring_typo() {
    // `compyte` is a transposition typo — the OLD substring matcher missed it;
    // edit-distance (cutoff 0.6) suggests `compute`.
    let repo = polyglot_repo();
    let out = tldr_cmd()
        .args(["context", "compyte", "-f", "text"])
        .current_dir(repo.path())
        .output()
        .expect("spawn tldr");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Did you mean") && stderr.contains("compute"),
        "expected fuzzy `compute` suggestion for `compyte`, got: {stderr}"
    );
}

#[test]
fn batch_all_hit_one_block_each() {
    let repo = polyglot_repo();
    let out = tldr_cmd()
        .args(["context", "compute", "helper", "add", "-f", "text", "--depth", "1"])
        .current_dir(repo.path())
        .output()
        .expect("spawn tldr");
    assert!(out.status.success(), "batch all-hit must exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        count_context_headers(&stdout),
        3,
        "expected 3 context blocks (one per symbol), got:\n{stdout}"
    );
}

#[test]
fn batch_partial_hits_stdout_misses_stderr_exit_zero() {
    let repo = polyglot_repo();
    let out = tldr_cmd()
        .args(["context", "compute", "nonexistent_xyz", "-f", "text"])
        .current_dir(repo.path())
        .output()
        .expect("spawn tldr");
    // Partial: at least one hit → exit 0.
    assert!(out.status.success(), "partial batch must exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(count_context_headers(&stdout), 1, "exactly one block on stdout: {stdout}");
    assert!(
        stderr.contains("nonexistent_xyz") && stderr.contains("not found"),
        "miss must go to stderr: {stderr}"
    );
    // The hit's context must NOT appear on stderr.
    assert!(!stderr.contains("# Code Context:"), "hit leaked to stderr: {stderr}");
}

#[test]
fn batch_all_miss_exit_nonzero() {
    let repo = polyglot_repo();
    let out = tldr_cmd()
        .args(["context", "nope1", "nope2", "-f", "text"])
        .current_dir(repo.path())
        .output()
        .expect("spawn tldr");
    assert!(!out.status.success(), "all-miss batch must exit non-zero");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(count_context_headers(&stdout), 0, "no blocks on stdout: {stdout}");
    // Two per-symbol miss lines on stderr.
    assert!(stderr.contains("nope1"), "nope1 miss missing: {stderr}");
    assert!(stderr.contains("nope2"), "nope2 miss missing: {stderr}");
}

#[test]
fn lang_all_token_accepted() {
    let repo = polyglot_repo();
    // `--lang all` must parse (was rejected before) and resolve the rust fn.
    tldr_cmd()
        .args(["context", "compute_rs", "--lang", "all", "-f", "text"])
        .current_dir(repo.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("# Code Context: compute_rs"));
}

#[test]
fn lang_auto_token_accepted() {
    let repo = polyglot_repo();
    tldr_cmd()
        .args(["context", "compute", "--lang", "auto", "-f", "text"])
        .current_dir(repo.path())
        .assert()
        .success();
}

#[test]
fn depth_default_is_two() {
    let repo = polyglot_repo();
    // Default depth (no --depth) must render `depth=2` in the header.
    tldr_cmd()
        .args(["context", "compute", "-f", "text"])
        .current_dir(repo.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("depth=2"));
}

#[test]
fn lang_all_equals_form_accepted() {
    // `--lang=all` (glued form) must also be accepted.
    let repo = polyglot_repo();
    tldr_cmd()
        .args(["context", "compute_rs", "--lang=all", "-f", "text"])
        .current_dir(repo.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("# Code Context: compute_rs"));
}

#[test]
fn explicit_language_token_accepted() {
    // An explicit language (`--lang rust`) still resolves.
    let repo = polyglot_repo();
    tldr_cmd()
        .args(["context", "compute_rs", "--lang", "rust", "-f", "text"])
        .current_dir(repo.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("# Code Context: compute_rs"));
}

#[test]
fn invalid_explicit_language_rejected() {
    // A bogus explicit language is still a clap error (the auto/all pre-pass
    // only intercepts `auto` / `all`).
    let repo = polyglot_repo();
    let out = tldr_cmd()
        .args(["context", "compute", "--lang", "klingon", "-f", "text"])
        .current_dir(repo.path())
        .output()
        .expect("spawn tldr");
    assert!(!out.status.success());
    assert_eq!(out.status.code().unwrap_or(-1), 2, "clap rejects unknown lang");
}

#[test]
fn sibling_command_lang_all_still_rejected() {
    // No-regression guard: the `auto` / `all` pre-pass fires ONLY for
    // `context`. A non-context command must still reject `--lang all` exactly
    // as it did on the baseline.
    let repo = polyglot_repo();
    let out = tldr_cmd()
        .args(["complexity", "calc.py", "compute", "--lang", "all", "-q"])
        .current_dir(repo.path())
        .output()
        .expect("spawn tldr");
    assert!(!out.status.success(), "complexity --lang all must still error");
}

#[test]
fn qualified_class_dot_method_resolves() {
    let repo = polyglot_repo();
    tldr_cmd()
        .args(["context", "Calculator.add", "-f", "text"])
        .current_dir(repo.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("# Code Context: Calculator.add"));
}

#[test]
fn cross_convention_struct_dot_method_resolves() {
    // `Engine.run` (dot form) — the Rust call graph stores `Engine::run`, so
    // this exercises the narrowed strip-and-retry hop end-to-end.
    let repo = polyglot_repo();
    tldr_cmd()
        .args(["context", "Engine.run", "--lang", "rust", "-f", "text"])
        .current_dir(repo.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("# Code Context: Engine.run"));
}

#[test]
fn trailing_directory_positional_is_treated_as_path() {
    // Back-compat: `tldr context compute .` — the trailing `.` (an existing
    // dir) is the project root, not a second symbol → single-symbol mode.
    let repo = polyglot_repo();
    let out = tldr_cmd()
        .args(["context", "compute", ".", "-f", "text"])
        .current_dir(repo.path())
        .output()
        .expect("spawn tldr");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(count_context_headers(&stdout), 1, "expected single block: {stdout}");
}

#[test]
fn zero_entries_rejected_by_clap() {
    // `tldr context` with no symbol must be a clap parse error (exit 2).
    let dir = TempDir::new().unwrap();
    let out = tldr_cmd()
        .args(["context"])
        .current_dir(dir.path())
        .output()
        .expect("spawn tldr");
    assert!(!out.status.success(), "zero entries must fail");
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(code, 2, "clap arg error should be exit 2, got {code}");
}

#[test]
fn explicit_project_flag_keeps_all_positionals_as_symbols() {
    // With `--project`, a trailing `.`-like token is NOT popped — all
    // positionals are symbols. Here `compute helper` both resolve.
    let repo = polyglot_repo();
    let proj = repo.path().to_str().unwrap();
    let out = tldr_cmd()
        .args(["context", "compute", "helper", "--project", proj, "-f", "text", "--depth", "1"])
        .output()
        .expect("spawn tldr");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(count_context_headers(&stdout), 2, "expected 2 blocks: {stdout}");
}
