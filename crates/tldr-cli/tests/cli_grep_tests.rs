//! CLI integration tests for the `tldr grep` command (Python `tldr search`
//! parity).
//!
//! Parity oracle: `python -m tldr.cli search <args>` (from
//! /Users/tuan/dev/llm-tldr). These assertions were diffed against the live
//! oracle while authoring (see thoughts/verification/search-grep.md).

use std::fs;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Git-initialized fixture matching the verification doc.
fn fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(dir.path())
        .status()
        .unwrap();
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::create_dir_all(dir.path().join("lib")).unwrap();
    fs::write(
        dir.path().join("src/app.py"),
        "def foo(): pass\ndef bar(): pass\nfoobar = 1\nvalue = 42\nid3 = \"abc\"\npipe = \"a|b\"\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("src/notes.txt"),
        "TODO: first\nnothing here\nTODO: third\n",
    )
    .unwrap();
    fs::write(dir.path().join("src/indent.py"), "    indented = 1\n").unwrap();
    fs::write(
        dir.path().join("lib/util.js"),
        "foo_in_lib = 1\nutil = 2\n",
    )
    .unwrap();
    dir
}

fn run(dir: &TempDir, args: &[&str]) -> std::process::Output {
    tldr_cmd()
        .arg("grep")
        .args(args)
        .current_dir(dir.path())
        .output()
        .unwrap()
}

fn json_array(out: &std::process::Output) -> Vec<Value> {
    let s = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<Value>(&s)
        .unwrap_or_else(|e| panic!("not JSON: {e}\nstdout was: {s}"))
        .as_array()
        .expect("expected JSON array")
        .clone()
}

#[test]
fn emits_flat_array_shape() {
    let dir = fixture();
    let out = run(&dir, &["foo", "src/app.py"]);
    assert!(out.status.success());
    let arr = json_array(&out);
    assert_eq!(arr.len(), 2);
    // Each item is {file, line, content}.
    let first = &arr[0];
    assert_eq!(first["file"], "app.py");
    assert_eq!(first["line"], 1);
    assert_eq!(first["content"], "def foo(): pass");
    assert!(first.get("context").is_none());
}

#[test]
fn escaped_pipe_alternation() {
    let dir = fixture();
    let out = run(&dir, &[r"foo\|bar", "src/app.py"]);
    let arr = json_array(&out);
    let lines: Vec<i64> = arr.iter().map(|v| v["line"].as_i64().unwrap()).collect();
    assert_eq!(lines, vec![1, 2, 3]);
}

#[test]
fn bare_pipe_alternation_identical() {
    let dir = fixture();
    let out = run(&dir, &["foo|bar", "src/app.py"]);
    let arr = json_array(&out);
    let lines: Vec<i64> = arr.iter().map(|v| v["line"].as_i64().unwrap()).collect();
    assert_eq!(lines, vec![1, 2, 3]);
}

#[test]
fn ignore_case_flag() {
    let dir = fixture();
    let ci = run(&dir, &["-i", "todo", "src/notes.txt"]);
    assert_eq!(json_array(&ci).len(), 2);
    let cs = run(&dir, &["todo", "src/notes.txt"]);
    assert_eq!(json_array(&cs).len(), 0);
}

#[test]
fn include_filters_extensions() {
    let dir = fixture();
    // Only .txt across the repo.
    let out = run(&dir, &["TODO", ".", "--include", "*.txt"]);
    let arr = json_array(&out);
    assert!(!arr.is_empty());
    assert!(arr
        .iter()
        .all(|v| v["file"].as_str().unwrap().ends_with(".txt")));
}

#[test]
fn include_bad_glob_exit_2() {
    let dir = fixture();
    let out = run(&dir, &["TODO", ".", "--include", "["]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unsupported --include glob"),
        "stderr: {stderr}"
    );
}

#[test]
fn exclude_dir_drops_dir() {
    let dir = fixture();
    let out = run(&dir, &["foo", ".", "--exclude-dir", "src"]);
    let arr = json_array(&out);
    // src/ dropped; lib/util.js (foo_in_lib) remains.
    assert!(arr
        .iter()
        .all(|v| !v["file"].as_str().unwrap().starts_with("src")));
    assert!(arr
        .iter()
        .any(|v| v["file"].as_str().unwrap().contains("util.js")));
}

#[test]
fn multi_path_merge_dir_and_dir() {
    let dir = fixture();
    let out = run(&dir, &["foo", "src", "lib"]);
    let arr = json_array(&out);
    let files: Vec<&str> = arr.iter().map(|v| v["file"].as_str().unwrap()).collect();
    // dir args get join(p, rel) prefixing.
    assert!(files.contains(&"src/app.py"));
    assert!(files.contains(&"lib/util.js"));
}

#[test]
fn multi_path_dir_and_file_prefix_rules() {
    let dir = fixture();
    let out = run(&dir, &["foo", "src", "lib/util.js"]);
    let arr = json_array(&out);
    let files: Vec<&str> = arr.iter().map(|v| v["file"].as_str().unwrap()).collect();
    // dir arg -> join; file arg -> verbatim path argument.
    assert!(files.contains(&"src/app.py"));
    assert!(files.contains(&"lib/util.js"));
}

#[test]
fn single_dir_basename() {
    let dir = fixture();
    let out = run(&dir, &["foo", "src"]);
    let arr = json_array(&out);
    // Single dir -> root-relative basename "app.py".
    assert!(arr.iter().all(|v| v["file"] == "app.py"));
    assert_eq!(arr.len(), 2);
}

#[test]
fn max_count_budget_spans_paths() {
    let dir = fixture();
    // src has 2 foo hits; -m 2 should fill from src and stop before lib.
    let out = run(&dir, &["foo", "src", "lib", "-m", "2"]);
    let arr = json_array(&out);
    assert_eq!(arr.len(), 2);
    assert!(arr
        .iter()
        .all(|v| v["file"].as_str().unwrap().starts_with("src")));
}

#[test]
fn single_file_basename_and_trim() {
    let dir = fixture();
    let out = run(&dir, &["indented", "src/indent.py"]);
    let arr = json_array(&out);
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["file"], "indent.py");
    assert_eq!(arr[0]["content"], "indented = 1"); // trimmed
}

#[test]
fn max_count_single_hit() {
    let dir = fixture();
    let out = run(&dir, &["foo", "src/app.py", "-m", "1"]);
    let arr = json_array(&out);
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["line"], 1);
}

#[test]
fn missing_path_exit_1() {
    let dir = fixture();
    let out = run(&dir, &["foo", "src/nonexistent"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("path 'src/nonexistent' not found"),
        "stderr: {stderr}"
    );
}

#[test]
fn zero_hits_empty_array_exit_0() {
    let dir = fixture();
    let out = run(&dir, &["zzzznomatch", "src/app.py"]);
    assert!(out.status.success());
    let arr = json_array(&out);
    assert!(arr.is_empty());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "[]");
}

#[test]
fn invalid_pattern_nonzero_exit() {
    let dir = fixture();
    let out = run(&dir, &["foo(", "src/app.py"]);
    assert!(!out.status.success());
}

#[test]
fn fallback_escaped_paren_matches() {
    let dir = fixture();
    let out = run(&dir, &[r"foo\(", "src/app.py"]);
    assert!(out.status.success());
    let arr = json_array(&out);
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["line"], 1);
}

#[test]
fn literal_pipe_class() {
    let dir = fixture();
    let out = run(&dir, &["[|]", "src/app.py"]);
    let arr = json_array(&out);
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["line"], 6);
}

#[test]
fn no_ignore_reveals_tldrignored() {
    let dir = TempDir::new().unwrap();
    Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(dir.path())
        .status()
        .unwrap();
    fs::write(dir.path().join(".tldrignore"), "skipme/\n").unwrap();
    fs::create_dir_all(dir.path().join("skipme")).unwrap();
    fs::create_dir_all(dir.path().join("keep")).unwrap();
    fs::write(dir.path().join("skipme/b.py"), "TODO\n").unwrap();
    fs::write(dir.path().join("keep/a.py"), "TODO\n").unwrap();

    let honored = run(&dir, &["TODO", "."]);
    let files: Vec<String> = json_array(&honored)
        .iter()
        .map(|v| v["file"].as_str().unwrap().to_string())
        .collect();
    assert!(files.iter().any(|f| f.contains("keep")));
    assert!(!files.iter().any(|f| f.contains("skipme")));

    let revealed = run(&dir, &["TODO", ".", "--no-ignore"]);
    let files2: Vec<String> = json_array(&revealed)
        .iter()
        .map(|v| v["file"].as_str().unwrap().to_string())
        .collect();
    assert!(files2.iter().any(|f| f.contains("skipme")));
}

#[test]
fn exclude_dir_composes_with_no_ignore() {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join("a")).unwrap();
    fs::write(dir.path().join("a/x.py"), "TODO\n").unwrap();
    fs::write(dir.path().join("top.py"), "TODO\n").unwrap();
    let out = run(&dir, &["TODO", ".", "--no-ignore", "--exclude-dir", "a"]);
    let arr = json_array(&out);
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["file"], "top.py");
}

#[test]
fn context_lines_emitted() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), "l1\nl2\nMATCH\nl4\nl5\n").unwrap();
    let out = run(&dir, &["MATCH", "a.txt", "-C", "1"]);
    let arr = json_array(&out);
    assert_eq!(arr.len(), 1);
    let ctx = arr[0]["context"].as_array().unwrap();
    let ctx: Vec<&str> = ctx.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(ctx, vec!["l2", "MATCH", "l4"]);
}
