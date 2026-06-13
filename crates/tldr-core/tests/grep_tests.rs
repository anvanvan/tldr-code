//! Integration tests for the grep-canonical search engine
//! (`tldr_core::grep_search` / `normalize_grep_pattern`), encoding the Python
//! `tldr search` oracle behavior.
//!
//! Parity oracle: `python -m tldr.cli search <args>` (from
//! /Users/tuan/dev/llm-tldr) JSON vs these expectations.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;
use tldr_core::{grep_search, normalize_grep_pattern};

fn exts(list: &[&str]) -> HashSet<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// Create a git-initialized temp repo with the standard verification fixture.
fn fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    std::process::Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(dir.path())
        .status()
        .unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("src/app.py"),
        "def foo(): pass\ndef bar(): pass\nfoobar = 1\nvalue = 42\nid3 = \"abc\"\npipe = \"a|b\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("src/notes.txt"),
        "TODO: first\nnothing here\nTODO: third\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("src/indent.py"), "    indented = 1\n").unwrap();
    dir
}

// ---- normalize_grep_pattern table (verified against the Python oracle) ----

#[test]
fn normalize_escaped_pipe_to_alternation() {
    assert_eq!(normalize_grep_pattern(r"foo\|bar"), "foo|bar");
}

#[test]
fn normalize_bare_pipe_unchanged() {
    assert_eq!(normalize_grep_pattern(r"foo|bar"), "foo|bar");
}

#[test]
fn normalize_d_to_ascii_class() {
    assert_eq!(normalize_grep_pattern(r"\d+"), "[0-9]+");
}

#[test]
fn normalize_bracket_class_passthrough() {
    assert_eq!(normalize_grep_pattern(r"[\d]"), r"[\d]");
    assert_eq!(normalize_grep_pattern(r"[|]"), "[|]");
    assert_eq!(normalize_grep_pattern(r"[(]"), "[(]");
}

#[test]
fn normalize_double_backslash_literal() {
    assert_eq!(normalize_grep_pattern(r"\\d"), r"\\d");
}

#[test]
fn normalize_escaped_parens() {
    assert_eq!(normalize_grep_pattern(r"foo\("), "foo(");
    assert_eq!(normalize_grep_pattern(r"foo\)"), "foo)");
}

#[test]
fn normalize_same_meaning_escapes_verbatim() {
    assert_eq!(normalize_grep_pattern(r"\."), r"\.");
    assert_eq!(normalize_grep_pattern(r"\w\s\b"), r"\w\s\b");
}

#[test]
fn normalize_trailing_backslash() {
    assert_eq!(normalize_grep_pattern(r"abc\"), r"abc\");
}

#[test]
fn normalize_negated_class_passthrough() {
    assert_eq!(normalize_grep_pattern(r"[^\d]"), r"[^\d]");
}

#[test]
fn normalize_literal_first_bracket() {
    // ] as the first class member is a literal, not the terminator.
    assert_eq!(normalize_grep_pattern(r"[]\d]"), r"[]\d]");
}

// ---- engine behaviors ----

#[test]
fn alternation_via_escaped_pipe_matches_three_lines() {
    let dir = fixture();
    let f = dir.path().join("src/app.py");
    let hits = grep_search(r"foo\|bar", &f, None, 0, 0, 0, false, &[], true, &[]).unwrap();
    let lines: Vec<u32> = hits.iter().map(|h| h.line).collect();
    assert_eq!(lines, vec![1, 2, 3]);
}

#[test]
fn bare_pipe_alternation_identical() {
    let dir = fixture();
    let f = dir.path().join("src/app.py");
    let hits = grep_search(r"foo|bar", &f, None, 0, 0, 0, false, &[], true, &[]).unwrap();
    let lines: Vec<u32> = hits.iter().map(|h| h.line).collect();
    assert_eq!(lines, vec![1, 2, 3]);
}

#[test]
fn digit_class_matches_numeric_lines() {
    let dir = fixture();
    let f = dir.path().join("src/app.py");
    let hits = grep_search(r"\d+", &f, None, 0, 0, 0, false, &[], true, &[]).unwrap();
    let lines: Vec<u32> = hits.iter().map(|h| h.line).collect();
    assert_eq!(lines, vec![3, 4, 5]);
}

#[test]
fn d_is_ascii_only() {
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("a.txt");
    std::fs::write(&f, "abc123\n\u{0664}\u{0665}\u{0666}\n").unwrap();
    let hits = grep_search(r"\d", &f, None, 0, 0, 0, false, &[], true, &[]).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].line, 1);
}

#[test]
fn literal_pipe_class_only_pipe_line() {
    let dir = fixture();
    let f = dir.path().join("src/app.py");
    let hits = grep_search(r"[|]", &f, None, 0, 0, 0, false, &[], true, &[]).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].line, 6);
}

#[test]
fn escaped_paren_literal_matches() {
    let dir = fixture();
    let f = dir.path().join("src/app.py");
    let hits = grep_search(r"foo\(", &f, None, 0, 0, 0, false, &[], true, &[]).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].line, 1);
}

#[test]
fn compile_fallback_rescues_intentional_escape() {
    // 'foo\(' normalizes to 'foo(' (fails); fallback to original literal paren.
    let dir = fixture();
    let f = dir.path().join("src/app.py");
    let hits = grep_search(r"foo\(", &f, None, 0, 0, 0, false, &[], true, &[]).unwrap();
    assert_eq!(hits.len(), 1);
}

#[test]
fn invalid_regex_errors() {
    let dir = fixture();
    let f = dir.path().join("src/app.py");
    let res = grep_search("foo(", &f, None, 0, 0, 0, false, &[], true, &[]);
    assert!(res.is_err());
}

#[test]
fn ignore_case_matches_both() {
    let dir = fixture();
    let f = dir.path().join("src/notes.txt");
    let ci = grep_search("todo", &f, None, 0, 0, 0, true, &[], true, &[]).unwrap();
    assert_eq!(ci.len(), 2);
    let cs = grep_search("todo", &f, None, 0, 0, 0, false, &[], true, &[]).unwrap();
    assert_eq!(cs.len(), 0);
}

#[test]
fn single_file_basename_and_trim() {
    let dir = fixture();
    let f = dir.path().join("src/indent.py");
    let hits = grep_search("indented", &f, None, 0, 0, 0, false, &[], true, &[]).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].file, PathBuf::from("indent.py"));
    assert_eq!(hits[0].content, "indented = 1");
}

#[test]
fn single_file_ignores_include() {
    let dir = fixture();
    let f = dir.path().join("src/notes.txt");
    // .py filter would exclude .txt in dir mode, but single-file skips it.
    let hits = grep_search(
        "TODO",
        &f,
        Some(&exts(&[".py"])),
        0,
        0,
        0,
        false,
        &[],
        true,
        &[],
    )
    .unwrap();
    assert_eq!(hits.len(), 2);
}

#[test]
fn dir_mode_root_relative_file() {
    let dir = fixture();
    let hits = grep_search(
        "foo",
        &dir.path().join("src"),
        None,
        0,
        0,
        0,
        false,
        &[],
        false,
        &[],
    )
    .unwrap();
    assert!(hits.iter().all(|h| h.file == PathBuf::from("app.py")));
    assert_eq!(hits.len(), 2);
}

#[test]
fn max_results_cap() {
    let dir = fixture();
    let f = dir.path().join("src/app.py");
    let hits = grep_search("foo", &f, None, 0, 1, 0, false, &[], true, &[]).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].line, 1);
}

#[test]
fn max_results_zero_is_unlimited() {
    let dir = fixture();
    let f = dir.path().join("src/app.py");
    let hits = grep_search("foo", &f, None, 0, 0, 0, false, &[], true, &[]).unwrap();
    assert_eq!(hits.len(), 2); // lines 1, 3
}

#[test]
fn ext_filter_dir_mode() {
    let dir = fixture();
    let hits = grep_search(
        "TODO",
        dir.path(),
        Some(&exts(&[".txt"])),
        0,
        0,
        0,
        false,
        &[],
        false,
        &[],
    )
    .unwrap();
    assert!(hits.iter().all(|h| h.file.to_string_lossy().ends_with(".txt")));
    assert_eq!(hits.len(), 2);
}

#[test]
fn exclude_dir_drops_component() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::create_dir_all(dir.path().join("lib")).unwrap();
    std::fs::write(dir.path().join("src/a.py"), "TODO\n").unwrap();
    std::fs::write(dir.path().join("lib/b.py"), "TODO\n").unwrap();
    let hits = grep_search(
        "TODO",
        dir.path(),
        None,
        0,
        0,
        0,
        false,
        &["src".to_string()],
        false,
        &[],
    )
    .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].file, PathBuf::from("lib/b.py"));
}

#[test]
fn exclude_dir_composes_with_no_ignore() {
    // --exclude-dir is independent of the ignore spec.
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("a")).unwrap();
    std::fs::write(dir.path().join("a/x.py"), "TODO\n").unwrap();
    std::fs::write(dir.path().join("top.py"), "TODO\n").unwrap();
    let hits = grep_search(
        "TODO",
        dir.path(),
        None,
        0,
        0,
        0,
        false,
        &["a".to_string()],
        false, // no ignore
        &[],
    )
    .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].file, PathBuf::from("top.py"));
}

#[test]
fn skip_dirs_vendor_dropped_even_without_ignore() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("vendor")).unwrap();
    std::fs::write(dir.path().join("vendor/v.py"), "TODO\n").unwrap();
    std::fs::write(dir.path().join("keep.py"), "TODO\n").unwrap();
    let hits = grep_search(
        "TODO",
        dir.path(),
        None,
        0,
        0,
        0,
        false,
        &[],
        false,
        &[],
    )
    .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].file, PathBuf::from("keep.py"));
}

#[test]
fn gitignore_honored() {
    let dir = TempDir::new().unwrap();
    Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(dir.path())
        .status()
        .unwrap();
    std::fs::write(dir.path().join(".gitignore"), "secret/\n").unwrap();
    std::fs::create_dir_all(dir.path().join("secret")).unwrap();
    std::fs::create_dir_all(dir.path().join("keep")).unwrap();
    std::fs::write(dir.path().join("secret/s.py"), "TODO\n").unwrap();
    std::fs::write(dir.path().join("keep/a.py"), "TODO\n").unwrap();

    let with_ignore =
        grep_search("TODO", dir.path(), None, 0, 0, 0, false, &[], true, &[]).unwrap();
    let files: HashSet<_> = with_ignore.iter().map(|h| h.file.clone()).collect();
    assert!(files.contains(&PathBuf::from("keep/a.py")));
    assert!(!files.contains(&PathBuf::from("secret/s.py")));

    let no_ignore =
        grep_search("TODO", dir.path(), None, 0, 0, 0, false, &[], false, &[]).unwrap();
    let files2: HashSet<_> = no_ignore.iter().map(|h| h.file.clone()).collect();
    assert!(files2.contains(&PathBuf::from("secret/s.py")));
}

#[test]
fn tldrignore_honored() {
    let dir = TempDir::new().unwrap();
    Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(dir.path())
        .status()
        .unwrap();
    std::fs::write(dir.path().join(".tldrignore"), "skipme/\n").unwrap();
    std::fs::create_dir_all(dir.path().join("skipme")).unwrap();
    std::fs::create_dir_all(dir.path().join("keep")).unwrap();
    std::fs::write(dir.path().join("skipme/b.py"), "TODO\n").unwrap();
    std::fs::write(dir.path().join("keep/a.py"), "TODO\n").unwrap();

    let hits = grep_search("TODO", dir.path(), None, 0, 0, 0, false, &[], true, &[]).unwrap();
    let files: HashSet<_> = hits.iter().map(|h| h.file.clone()).collect();
    assert!(files.contains(&PathBuf::from("keep/a.py")), "keep present");
    assert!(
        !files.contains(&PathBuf::from("skipme/b.py")),
        ".tldrignore honored"
    );
}

#[test]
fn cli_ignore_pattern_adds_exclusion() {
    let dir = TempDir::new().unwrap();
    Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(dir.path())
        .status()
        .unwrap();
    std::fs::write(dir.path().join("a.txt"), "TODO\n").unwrap();
    std::fs::write(dir.path().join("b.py"), "TODO\n").unwrap();

    // --ignore "*.txt" should drop the .txt file.
    let hits = grep_search(
        "TODO",
        dir.path(),
        None,
        0,
        0,
        0,
        false,
        &[],
        true,
        &["*.txt".to_string()],
    )
    .unwrap();
    let files: HashSet<_> = hits.iter().map(|h| h.file.clone()).collect();
    assert!(files.contains(&PathBuf::from("b.py")));
    assert!(!files.contains(&PathBuf::from("a.txt")), "--ignore *.txt applied");
}

#[test]
fn context_lines_window() {
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("a.txt");
    std::fs::write(&f, "l1\nl2\nMATCH\nl4\nl5\n").unwrap();
    let hits = grep_search("MATCH", &f, None, 1, 0, 0, false, &[], true, &[]).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].context.as_ref().unwrap(),
        &vec!["l2".to_string(), "MATCH".to_string(), "l4".to_string()]
    );
}
