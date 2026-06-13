//! fastedit CLI-contract guard tests (FORK-ONLY — exclude from upstream PRs).
//!
//! `fastedit` (parcadei/fastedit, an MLX fast-apply Edit replacement) is a
//! DOWNSTREAM CONSUMER of this `tldr` binary: it resolves `tldr` via
//! `shutil.which("tldr")` (no env/config/flag override) and shells out for all
//! AST / reference / search work. These tests lock the EXACT CLI invocations and
//! stdout-JSON shapes fastedit depends on, so a future migration or refactor
//! cannot silently break it.
//!
//! WHY THIS FILE EXISTS: fastedit "fall-opens" on a contract mismatch — its
//! delete/rename/move caller-safety guards silently degrade to no-ops or skip
//! the safety check rather than erroring. A green test suite that does NOT
//! assert these shapes would therefore NOT catch a regression. These assertions
//! are the contract.
//!
//! Contract source (fastedit 0.5.0):
//!   inference/ast_utils.py  — get_ast_map / _get_ast_via_structure /
//!                             _enrich_parents_from_extract / _get_ast_via_extract
//!   inference/caller_safety.py, rename.py, move_to_file.py — references guards
//!   doctor.py — `tldr --version` (last whitespace token parsed as the version)
//!
//! Scope: `cargo test -p tldr-cli --test fastedit_contract`.

use serde_json::Value;
use std::fs;
use std::process::{Command, Output};
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn run(args: &[&str]) -> Output {
    tldr_cmd().args(args).output().unwrap()
}

fn json_stdout(out: &Output, ctx: &str) -> Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{ctx}: stdout is not sole valid JSON: {e}\n--stdout--\n{stdout}"))
}

/// A 2-file Python project: `a.py` defines `helper`, `b.py` imports and calls
/// it twice. `.git` anchors the project root so detection doesn't walk into the
/// shared temp parent.
fn project() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join(".git")).unwrap();
    fs::write(dir.path().join("a.py"), "def helper():\n    return 1\n").unwrap();
    fs::write(
        dir.path().join("b.py"),
        "from a import helper\n\n\ndef use():\n    return helper() + helper()\n",
    )
    .unwrap();
    dir
}

// ---- 1. structure --format compact|json ------------------------------------
// fastedit `_get_ast_via_structure` (the PRIMARY AST path) reads
// files[0].definitions[] requiring name/kind/line_start/line_end/signature.
#[test]
fn contract_structure_definitions_shape_compact_and_json() {
    let dir = project();
    let f = dir.path().join("a.py");
    for fmt in ["compact", "json"] {
        let out = run(&["structure", f.to_str().unwrap(), "--format", fmt, "-q"]);
        assert!(out.status.success(), "structure --format {fmt} should exit 0");
        let v = json_stdout(&out, &format!("structure --format {fmt}"));
        let files = v["files"].as_array().expect("top-level files[]");
        assert!(!files.is_empty(), "files[] non-empty");
        let defs = files[0]["definitions"]
            .as_array()
            .expect("files[0].definitions[]");
        let d = defs
            .iter()
            .find(|d| d["name"] == "helper")
            .expect("definition for `helper`");
        for key in ["name", "kind", "line_start", "line_end", "signature"] {
            assert!(d.get(key).is_some(), "definition missing '{key}' ({fmt}): {d}");
        }
    }
}

// ---- 2. references --format json --scope --min-confidence --limit -----------
// fastedit caller_safety/rename/move_to_file read the top-level `references[]`
// and `definition`; rename uses column+end_column; the delete guard reads
// file/line/kind. All flags must be accepted.
#[test]
fn contract_references_shape_and_flags() {
    let dir = project();
    let out = run(&[
        "references",
        "helper",
        dir.path().to_str().unwrap(),
        "--format",
        "json",
        "--scope",
        "workspace",
        "--min-confidence",
        "0.9",
        "--limit",
        "10000",
    ]);
    assert!(out.status.success(), "references should exit 0");
    let v = json_stdout(&out, "references --scope workspace");
    assert!(v.get("definition").is_some(), "top-level 'definition' key");
    let refs = v["references"]
        .as_array()
        .expect("top-level 'references' array");
    assert!(!refs.is_empty(), "references[] non-empty");
    for r in refs {
        for key in ["file", "line", "column", "kind"] {
            assert!(r.get(key).is_some(), "reference missing '{key}': {r}");
        }
    }
    // The high-confidence AST call refs are exactly what fastedit renames; they
    // must carry the rewrite span (end_column) + confidence fastedit filters on.
    let calls: Vec<&Value> = refs.iter().filter(|r| r["kind"] == "call").collect();
    assert!(!calls.is_empty(), "expected at least one `call` reference");
    for r in &calls {
        assert!(r.get("end_column").is_some(), "call ref missing 'end_column': {r}");
        assert!(r.get("confidence").is_some(), "call ref missing 'confidence': {r}");
    }
    // --scope local|file must also parse + exit 0 (fastedit single-file rename
    // passes --scope file).
    for scope in ["file", "local"] {
        let o = run(&[
            "references",
            "helper",
            dir.path().join("b.py").to_str().unwrap(),
            "--format",
            "json",
            "--scope",
            scope,
            "--min-confidence",
            "0.9",
            "--limit",
            "10",
        ]);
        assert!(o.status.success(), "references --scope {scope} should exit 0");
    }
}

// ---- 3. search --format text --top-k (+ --regex/--hybrid): BM25, NOT grep ---
// fastedit `fast_search` uses `tldr search ... --top-k N` (and --regex/--hybrid)
// for ranked code search. `search` MUST stay BM25; grep-canonical is `grep`.
#[test]
fn contract_search_is_bm25_with_topk_and_modes() {
    let dir = project();
    let p = dir.path().to_str().unwrap();
    let out = run(&["search", "helper", p, "--format", "text", "--top-k", "5"]);
    assert!(
        out.status.success(),
        "search --top-k should exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    // BM25 envelope (results/score), NOT the flat grep {file,line,content} array.
    let out_json = run(&["search", "helper", p, "--format", "json", "--top-k", "5"]);
    let v = json_stdout(&out_json, "search --format json");
    assert!(
        v.get("results").is_some(),
        "search json must be the BM25 envelope with 'results'; got {v}"
    );
    assert!(
        v.get("search_mode").is_some() || v.get("total_results").is_some(),
        "search json must carry the BM25 envelope fields"
    );
    assert!(
        run(&["search", "helper", p, "--format", "text", "--top-k", "5", "--regex"])
            .status
            .success(),
        "search --regex should be accepted"
    );
    assert!(
        run(&["search", "helper", p, "--format", "text", "--top-k", "5", "--hybrid", "help"])
            .status
            .success(),
        "search --hybrid PATTERN should be accepted"
    );
}

// ---- grep is a SEPARATE command (flat {file,line,content}) ------------------
// The grep-canonical surface must NOT be folded into `search` (that is the
// Python-fork shape fastedit cannot use).
#[test]
fn contract_grep_is_separate_flat_array() {
    let dir = project();
    let out = run(&["grep", "helper", dir.path().to_str().unwrap(), "--format", "json"]);
    assert!(out.status.success(), "grep should exit 0");
    let v = json_stdout(&out, "grep --format json");
    let arr = v.as_array().expect("grep emits a flat top-level array");
    assert!(!arr.is_empty(), "grep should find `helper`");
    for h in arr {
        for key in ["file", "line", "content"] {
            assert!(h.get(key).is_some(), "grep hit missing '{key}': {h}");
        }
    }
}

// ---- 4. extract --format json: line_number on function/class/method ---------
// fastedit `_enrich_parents_from_extract` (runs after EVERY successful
// structure) reads classes[].methods[].line_number; `_get_ast_via_extract`
// (fallback) reads functions[].line_number + classes[].line_number. These are a
// value-identical alias of `line` (see tldr-core types.rs fastedit-compat).
#[test]
fn contract_extract_emits_line_number_for_fastedit() {
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("m.py");
    fs::write(
        &f,
        "def top():\n    return 1\n\n\nclass C:\n    def run(self):\n        return 2\n",
    )
    .unwrap();
    let out = run(&["extract", f.to_str().unwrap(), "--format", "json", "-q"]);
    assert!(out.status.success(), "extract should exit 0");
    let v = json_stdout(&out, "extract --format json");

    let func = &v["functions"].as_array().expect("functions[]")[0];
    assert!(func.get("line_number").is_some(), "function missing line_number: {func}");
    assert_eq!(func["line_number"], func["line"], "function line_number must equal line");

    let cls = &v["classes"].as_array().expect("classes[]")[0];
    assert!(cls.get("line_number").is_some(), "class missing line_number: {cls}");
    assert_eq!(cls["line_number"], cls["line"], "class line_number must equal line");

    let method = &cls["methods"].as_array().expect("methods[]")[0];
    assert!(method.get("line_number").is_some(), "method missing line_number: {method}");
    assert_eq!(method["line_number"], method["line"], "method line_number must equal line");
}

// ---- 5. --version parseable as `tldr X.Y.Z` --------------------------------
// fastedit doctor reads the LAST whitespace token of stdout as the version.
#[test]
fn contract_version_is_parseable_semver() {
    let out = run(&["--version"]);
    assert!(out.status.success(), "--version should exit 0");
    let s = String::from_utf8_lossy(&out.stdout);
    let last = s.split_whitespace().last().expect("a version token on stdout");
    let parts: Vec<&str> = last.split('.').collect();
    assert_eq!(parts.len(), 3, "version token '{last}' is not X.Y.Z");
    assert!(
        parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())),
        "version token '{last}' has non-numeric components"
    );
}

// ---- general: stdout is SOLE JSON; advisories go to stderr -----------------
// Several fastedit paths json.loads() the entire stdout; trailing human text
// after the JSON would break the parse. The bare-extract >5-symbol advisory
// must land on stderr, leaving stdout clean.
#[test]
fn contract_stdout_clean_json_advisory_on_stderr() {
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("many.py");
    let mut src = String::new();
    for i in 0..7 {
        src.push_str(&format!("def f{i}():\n    return {i}\n\n\n"));
    }
    fs::write(&f, &src).unwrap();
    // No -q: the >5-symbol advisory fires. stdout must remain sole valid JSON.
    let out = run(&["extract", f.to_str().unwrap(), "--format", "json"]);
    assert!(out.status.success(), "extract should exit 0");
    let _v = json_stdout(&out, "bare extract (advisory active)"); // panics if stdout has trailing text
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("symbol") || stderr.contains("extract") || stderr.contains("filter"),
        "expected a >5-symbol advisory on stderr, got: {stderr:?}"
    );
}
