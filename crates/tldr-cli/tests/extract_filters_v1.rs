//! Area 2 — extract-filters integration tests.
//!
//! Ports the Python oracle behavior of `tldr extract --function/--method/--class`
//! (`api.py:extract_file_with_code`) and the bare-extract `>5`-symbol stderr
//! advisory (`cli.py:1022-1034`). The Python reference was captured with the
//! editable dev install at /Users/tuan/dev/llm-tldr.
//!
//! Scope: `cargo test -p tldr-cli extract`.

use assert_cmd::prelude::*;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// sample.py with 8 symbols: 2 top-level funcs + Widget(3 methods) + Gadget(1).
const SAMPLE_PY: &str = r#""""Module docstring."""
import os
from typing import List


def top_level_one(a, b):
    """First top-level function."""
    return a + b


def top_level_two(x):
    return x * 2


class Widget:
    """A widget."""

    def __init__(self, name):
        self.name = name

    def render(self):
        return f"<{self.name}>"

    def hidden_method(self):
        return None


class Gadget:
    def spin(self):
        return "spinning"
"#;

fn write_sample(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("sample.py");
    fs::write(&p, SAMPLE_PY).unwrap();
    p
}

fn run_json(args: &[&str]) -> (Value, String) {
    let mut cmd = tldr_cmd();
    cmd.args(args);
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("bad json from {:?}: {e}\nstdout={stdout}", args));
    (v, stderr)
}

// B1: --function NAME → compact code-first dict, no imports/call_graph.
#[test]
fn b1_function_compact_with_code() {
    let dir = TempDir::new().unwrap();
    let f = write_sample(&dir);
    let (v, _err) = run_json(&["extract", f.to_str().unwrap(), "--function", "top_level_one", "-q"]);

    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("file_path"));
    assert!(obj.contains_key("language"));
    assert!(obj.contains_key("functions"));
    assert!(!obj.contains_key("classes"), "no classes key when empty");
    assert!(!obj.contains_key("imports"), "imports dropped on filter");
    assert!(!obj.contains_key("call_graph"), "call_graph dropped on filter");

    let funcs = v["functions"].as_array().unwrap();
    assert_eq!(funcs.len(), 1);
    assert_eq!(funcs[0]["name"], "top_level_one");
    let code = funcs[0]["code"].as_str().unwrap();
    assert!(code.starts_with("def top_level_one(a, b):"));
    assert!(code.contains("return a + b"));
}

// B2: --method Class.method → narrow to one method, class shell retained, method code.
#[test]
fn b2_method_narrowed_with_code() {
    let dir = TempDir::new().unwrap();
    let f = write_sample(&dir);
    let (v, _err) = run_json(&["extract", f.to_str().unwrap(), "--method", "Widget.render", "-q"]);

    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("classes"));
    assert!(!obj.contains_key("functions"), "no functions on method filter");
    assert!(!obj.contains_key("imports"));
    assert!(!obj.contains_key("call_graph"));

    let classes = v["classes"].as_array().unwrap();
    assert_eq!(classes.len(), 1);
    assert_eq!(classes[0]["name"], "Widget");
    // No class-level code on a method filter.
    assert!(classes[0].as_object().unwrap().get("code").is_none());
    let methods = classes[0]["methods"].as_array().unwrap();
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0]["name"], "render");
    let code = methods[0]["code"].as_str().unwrap();
    assert!(code.contains("def render(self):"));
}

// B3: --class Name → class shell + all methods, code on class and each method.
#[test]
fn b3_class_all_methods_with_code() {
    let dir = TempDir::new().unwrap();
    let f = write_sample(&dir);
    let (v, _err) = run_json(&["extract", f.to_str().unwrap(), "--class", "Widget", "-q"]);

    let classes = v["classes"].as_array().unwrap();
    assert_eq!(classes.len(), 1);
    let c = &classes[0];
    assert_eq!(c["name"], "Widget");
    let class_code = c["code"].as_str().expect("class filter injects class code");
    assert!(class_code.starts_with("class Widget:"));
    let methods = c["methods"].as_array().unwrap();
    assert_eq!(methods.len(), 3, "all 3 Widget methods present");
    for m in methods {
        assert!(m["code"].as_str().is_some(), "each method carries code");
    }
}

// B6: --function fallback to class methods when no top-level fn matches.
#[test]
fn b6_function_fallback_to_method() {
    let dir = TempDir::new().unwrap();
    let f = write_sample(&dir);
    // `render` is a method on Widget, not a top-level function.
    let (v, _err) = run_json(&["extract", f.to_str().unwrap(), "--function", "render", "-q"]);

    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("classes"), "fell back to classes");
    assert!(!obj.contains_key("functions"), "empty functions key dropped");
    let classes = v["classes"].as_array().unwrap();
    assert_eq!(classes.len(), 1);
    let methods = classes[0]["methods"].as_array().unwrap();
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0]["name"], "render");
    assert!(methods[0]["code"].as_str().is_some());
    // No class-level code on the function-fallback path.
    assert!(classes[0].as_object().unwrap().get("code").is_none());
}

// B8: dotless --method (incl. `::`) → only identity keys (no normalization).
#[test]
fn b8_dotless_method_empty() {
    let dir = TempDir::new().unwrap();
    let f = write_sample(&dir);

    for sel in ["NoDotHere", "Widget::render"] {
        let (v, _err) = run_json(&["extract", f.to_str().unwrap(), "--method", sel, "-q"]);
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 2, "only file_path + language for {sel}");
        assert!(obj.contains_key("file_path"));
        assert!(obj.contains_key("language"));
        assert!(!obj.contains_key("classes"));
        assert!(!obj.contains_key("functions"));
    }
}

// Filtered runs are stderr-silent (no advisory) even on an 8-symbol file.
#[test]
fn filtered_run_stderr_silent() {
    let dir = TempDir::new().unwrap();
    let f = write_sample(&dir);
    let mut cmd = tldr_cmd();
    cmd.args(["extract", f.to_str().unwrap(), "--function", "top_level_one"]);
    let out = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("symbols' metadata"),
        "filtered run must not emit the bare advisory; got: {stderr}"
    );
}

// Bare extract on >5 symbols → full ModuleInfo + 2-line stderr advisory.
#[test]
fn bare_advisory_over_five_symbols() {
    let dir = TempDir::new().unwrap();
    let f = write_sample(&dir); // 8 symbols
    let mut cmd = tldr_cmd();
    // No -q so the advisory is allowed.
    cmd.args(["extract", f.to_str().unwrap()]);
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Full ModuleInfo shape on stdout.
    let v: Value = serde_json::from_str(&stdout).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("imports"), "bare keeps imports");
    assert!(obj.contains_key("call_graph"), "bare keeps call_graph");

    // 2-line advisory naming count, file, and all three flags.
    assert!(stderr.contains("tldr: extract dumped 8 symbols' metadata from"));
    assert!(stderr.contains(f.to_str().unwrap()));
    assert!(stderr.contains("Pass --function NAME / --method Class.method / --class Name to filter."));
}

// Advisory boundary: silent at exactly 5 symbols, fires at 6 (strictly > 5).
#[test]
fn advisory_boundary_five_vs_six() {
    let dir = TempDir::new().unwrap();

    // five.py: 3 funcs + 1 class + 1 method = 5 symbols.
    let five = dir.path().join("five.py");
    fs::write(
        &five,
        "def f1(): pass\ndef f2(): pass\ndef f3(): pass\nclass C:\n    def m1(self): pass\n",
    )
    .unwrap();
    let mut cmd = tldr_cmd();
    cmd.args(["extract", five.to_str().unwrap()]);
    let err5 = String::from_utf8_lossy(&cmd.output().unwrap().stderr).to_string();
    assert!(
        !err5.contains("symbols' metadata"),
        "5 symbols must be silent; got: {err5}"
    );

    // six.py: 4 funcs + 1 class + 1 method = 6 symbols.
    let six = dir.path().join("six.py");
    fs::write(
        &six,
        "def f1(): pass\ndef f2(): pass\ndef f3(): pass\ndef f4(): pass\nclass C:\n    def m1(self): pass\n",
    )
    .unwrap();
    let mut cmd = tldr_cmd();
    cmd.args(["extract", six.to_str().unwrap()]);
    let err6 = String::from_utf8_lossy(&cmd.output().unwrap().stderr).to_string();
    assert!(
        err6.contains("tldr: extract dumped 6 symbols' metadata from"),
        "6 symbols must emit advisory; got: {err6}"
    );
}

// --quiet suppresses the bare advisory.
#[test]
fn bare_advisory_suppressed_under_quiet() {
    let dir = TempDir::new().unwrap();
    let f = write_sample(&dir);
    let mut cmd = tldr_cmd();
    cmd.args(["extract", f.to_str().unwrap(), "-q"]);
    let stderr = String::from_utf8_lossy(&cmd.output().unwrap().stderr).to_string();
    assert!(
        !stderr.contains("symbols' metadata"),
        "--quiet suppresses advisory; got: {stderr}"
    );
}

// Help renders all three filter flags (clap field-name remap to --class etc).
#[test]
fn help_shows_filter_flags() {
    let mut cmd = tldr_cmd();
    cmd.args(["extract", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--class"))
        .stdout(predicate::str::contains("--function"))
        .stdout(predicate::str::contains("--method"));
}

// Text format on a filtered run renders the body (tldr-code-only surface).
#[test]
fn filtered_text_format_renders_body() {
    let dir = TempDir::new().unwrap();
    let f = write_sample(&dir);
    let mut cmd = tldr_cmd();
    cmd.args([
        "extract",
        f.to_str().unwrap(),
        "--function",
        "top_level_one",
        "--format",
        "text",
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("top_level_one"))
        .stdout(predicate::str::contains("return a + b"));
}
