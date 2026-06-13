#![cfg(feature = "semantic")]
//! Area-3 (semantic-surface) CLI parity tests for the reshaped flat `semantic`
//! command: `--path`, `--k` (alias of `-n`/`--top`), `--expand`, and
//! `--device {cpu,gpu}` (default gpu).
//!
//! Most assertions are parse-level (no model download): `--help` surface, the
//! pre-build `--device` validation error, and that the new flags/aliases are
//! ACCEPTED by clap (no "unexpected argument"). The real-embed end-to-end is
//! `#[ignore]` (requires a ~110MB model download).
//!
//! Oracle: Python `tldr semantic search --help` exposes
//! `--path`/`--k`/`--expand`/`--device`; the user-mandated deviation is the
//! `{cpu,gpu}` device label with a `gpu` default.

use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// `tldr semantic --help` must advertise all four new flags.
#[test]
fn help_lists_new_flags() {
    let output = tldr_cmd()
        .arg("semantic")
        .arg("--help")
        .output()
        .expect("tldr semantic --help executed");
    assert!(output.status.success(), "--help should exit 0");
    let help = String::from_utf8_lossy(&output.stdout);

    for flag in ["--path", "--k", "--expand", "--device"] {
        assert!(
            help.contains(flag),
            "`tldr semantic --help` must list {flag}; help was:\n{help}"
        );
    }
    // The back-compat aliases stay.
    for flag in ["--top", "--threshold", "--langs", "--no-cache"] {
        assert!(
            help.contains(flag),
            "`tldr semantic --help` must keep alias {flag}; help was:\n{help}"
        );
    }
}

/// `--device bogus` must fail fast with the device error BEFORE any index
/// build / model download (Device::resolve runs before SemanticIndex::build).
#[test]
fn invalid_device_errors_before_build() {
    let tmp = tempdir().unwrap();
    fs::write(tmp.path().join("a.rs"), "pub fn x() {}").unwrap();

    let output = tldr_cmd()
        .arg("semantic")
        .arg("any query")
        .arg(tmp.path())
        .arg("--device")
        .arg("bogus")
        .arg("--quiet")
        .output()
        .expect("tldr semantic executed");

    assert!(!output.status.success(), "bad device must be a non-zero exit");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("device") || stderr.contains("bogus"),
        "stderr should mention the invalid device; was:\n{stderr}"
    );
    // Must NOT have started downloading a model (fail fast before build).
    assert!(
        !stderr.contains("download") && !stderr.contains("Loading embedding model"),
        "invalid device should fail before any model load; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "must not panic; stderr:\n{stderr}"
    );
}

/// The new flags + aliases must be ACCEPTED by clap (no "unexpected argument").
/// We pass `--device cpu --k 3 --path . --expand` and only assert clap did not
/// reject the args. The command may still fail later (no model in CI) — we
/// scope the assertion to the arg-parsing layer.
#[test]
fn new_flags_are_accepted_by_clap() {
    let tmp = tempdir().unwrap();
    fs::write(tmp.path().join("a.rs"), "pub fn x() {}").unwrap();

    // Use an invalid device to short-circuit before model load while still
    // exercising that --k/--path/--expand parse (clap validates all args before
    // run()). If any of these were unknown flags, clap would emit "unexpected
    // argument" regardless of device.
    let output = tldr_cmd()
        .arg("semantic")
        .arg("any query")
        .arg("--path")
        .arg(tmp.path())
        .arg("--k")
        .arg("3")
        .arg("--expand")
        .arg("--device")
        .arg("bogus") // force pre-build exit, no download
        .arg("--quiet")
        .output()
        .expect("tldr semantic executed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "--path/--k/--expand must be accepted by clap; stderr:\n{stderr}"
    );
}

/// `-n`/`--top`/`-t` back-compat aliases still parse.
#[test]
fn legacy_aliases_still_parse() {
    let tmp = tempdir().unwrap();
    fs::write(tmp.path().join("a.rs"), "pub fn x() {}").unwrap();

    let output = tldr_cmd()
        .arg("semantic")
        .arg("any query")
        .arg(tmp.path())
        .arg("-n")
        .arg("3")
        .arg("-t")
        .arg("0.4")
        .arg("--device")
        .arg("bogus") // pre-build exit
        .arg("--quiet")
        .output()
        .expect("tldr semantic executed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "-n/-t aliases must still parse; stderr:\n{stderr}"
    );
}

// =============================================================================
// Real-embed end-to-end (model download) — IGNORED by default.
// =============================================================================

/// End-to-end over a mixed `.md` + `.rs` tree: the non-code file is indexed and
/// surfaces, `--expand` adds graph fields. Requires a ~110MB model download.
#[test]
#[ignore = "requires ~110MB model download"]
fn e2e_noncode_indexed_and_expand_fields() {
    let _ = std::fs::remove_dir_all("/private/tmp/.tldr");
    let tmp = tempdir().unwrap();
    Command::new("git")
        .arg("init")
        .current_dir(tmp.path())
        .output()
        .ok();
    fs::write(
        tmp.path().join("README.md"),
        "# Billing\nhandle malformed PDF invoice recovery\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("parser.rs"),
        "fn parse_invoice() { let _ = 1; }\n",
    )
    .unwrap();

    let output = tldr_cmd()
        .arg("semantic")
        .arg("malformed pdf invoice billing")
        .arg(tmp.path())
        .arg("--k")
        .arg("10")
        .arg("--threshold")
        .arg("0.0")
        .arg("--expand")
        .arg("--device")
        .arg("gpu") // best-effort, CPU fallback when CoreML absent
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .arg("--no-cache")
        .output()
        .expect("tldr semantic executed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "e2e should succeed; stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    // Non-code README.md should be in the index (and likely a result).
    assert!(stdout.contains("README.md"), "README.md should surface; stdout:\n{stdout}");
    // --expand should add graph fields.
    assert!(
        stdout.contains("\"calls\"") && stdout.contains("\"called_by\"") && stdout.contains("\"related\""),
        "--expand should add calls/called_by/related; stdout:\n{stdout}"
    );

    let _ = std::fs::remove_dir_all("/private/tmp/.tldr");
}
