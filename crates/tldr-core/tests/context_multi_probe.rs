//! context-batch (area 4): integration tests for `get_relevant_context_multi`
//! and `resolve_context_languages`.
//!
//! Oracle: Python `tldr context` on the polyglot verify fixture
//! (`/tmp/verify-context-batch-1`): first-hit-wins probing, all-miss with
//! fuzzy suggestions, `--lang all`, auto-detect, empty→python.

use std::fs;

use tldr_core::context::resolve::{
    get_relevant_context_multi, resolve_context_languages, MultiContextOutcome,
    SUPPORTED_CONTEXT_LANGUAGES,
};
use tldr_core::Language;
use tempfile::TempDir;

/// Build a polyglot project: a Python `calc.py` and a Rust `lib.rs` that each
/// define call-graph-connected functions.
fn polyglot_project() -> TempDir {
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
    dir
}

#[test]
fn first_hit_wins_python_symbol() {
    let dir = polyglot_project();
    let langs = [Language::Python, Language::Rust];
    let outcome =
        get_relevant_context_multi(dir.path(), "compute", 1, &langs, true);
    assert!(outcome.is_hit(), "expected a hit for python `compute`");
    if let MultiContextOutcome::Hit(ctx) = outcome {
        assert_eq!(ctx.entry_point, "compute");
        assert!(
            ctx.functions.iter().any(|f| f.name.ends_with("compute")),
            "expected `compute` in resolved functions: {:?}",
            ctx.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
    }
}

#[test]
fn first_hit_wins_rust_symbol_even_when_python_probed_first() {
    // Cross-language: the Rust symbol resolves even though Python is probed
    // first (the per-language probe scans the whole project tree).
    let dir = polyglot_project();
    let langs = [Language::Python, Language::Rust];
    let outcome =
        get_relevant_context_multi(dir.path(), "compute_rs", 1, &langs, true);
    assert!(outcome.is_hit(), "expected a hit for rust `compute_rs`");
}

#[test]
fn all_miss_carries_probed_langs_and_suggestions() {
    let dir = polyglot_project();
    let langs = [Language::Python, Language::Rust];
    // `compyte` is a transposition typo of `compute` — substring matching
    // would miss, edit-distance (cutoff 0.6) suggests `compute`.
    let outcome =
        get_relevant_context_multi(dir.path(), "compyte", 2, &langs, true);
    match outcome {
        MultiContextOutcome::Miss {
            entry,
            probed,
            suggestions,
        } => {
            assert_eq!(entry, "compyte");
            assert_eq!(probed, vec![Language::Python, Language::Rust]);
            assert!(
                suggestions.iter().any(|s| s == "compute"),
                "expected `compute` suggestion, got {:?}",
                suggestions
            );
        }
        MultiContextOutcome::Hit(_) => panic!("expected a miss for `compyte`"),
    }
}

#[test]
fn empty_language_list_is_a_clean_miss() {
    let dir = polyglot_project();
    let outcome = get_relevant_context_multi(dir.path(), "compute", 2, &[], true);
    match outcome {
        MultiContextOutcome::Miss {
            probed, ..
        } => assert!(probed.is_empty()),
        MultiContextOutcome::Hit(_) => panic!("empty probe list must miss"),
    }
}

#[test]
fn miss_message_shape_matches_python() {
    let dir = polyglot_project();
    let langs = [Language::Python, Language::Rust];
    let outcome =
        get_relevant_context_multi(dir.path(), "compyte", 2, &langs, true);
    let msg = outcome.miss_message().expect("miss should render a message");
    assert!(
        msg.starts_with("Function 'compyte' not found in project (probed: python, rust)"),
        "unexpected miss message: {msg}"
    );
    assert!(msg.contains("Did you mean: compute?"), "missing suggestion clause: {msg}");
}

#[test]
fn resolve_languages_all_is_full_supported_set() {
    let langs = resolve_context_languages("all", std::path::Path::new(".")).unwrap();
    assert_eq!(langs, SUPPORTED_CONTEXT_LANGUAGES.to_vec());
    // Probe set is the 11 call-graph languages.
    assert_eq!(langs.len(), 11);
    assert!(langs.contains(&Language::Python));
    assert!(langs.contains(&Language::Rust));
}

#[test]
fn resolve_languages_auto_picks_detected_dominant() {
    // A Rust-dominant project: `auto` resolves to the detected dominant
    // language (a single probe; cross-language symbols still resolve because
    // each probe scans the whole tree).
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname=\"x\"\nversion=\"0.1.0\"\n").unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
    let langs = resolve_context_languages("auto", dir.path()).unwrap();
    assert_eq!(langs, vec![Language::Rust], "auto probe set: {:?}", langs);
}

#[test]
fn resolve_languages_auto_empty_project_falls_back_to_python() {
    let dir = TempDir::new().unwrap();
    // No source files at all.
    let langs = resolve_context_languages("auto", dir.path()).unwrap();
    assert_eq!(langs, vec![Language::Python]);
}

#[test]
fn resolve_languages_explicit() {
    assert_eq!(
        resolve_context_languages("rust", std::path::Path::new(".")).unwrap(),
        vec![Language::Rust]
    );
}

#[test]
fn resolve_languages_unknown_explicit_errors() {
    assert!(resolve_context_languages("klingon", std::path::Path::new(".")).is_err());
}
