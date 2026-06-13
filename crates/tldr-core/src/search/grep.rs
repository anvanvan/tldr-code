//! Grep-canonical text search (Python `tldr search` parity).
//!
//! This is a distinct engine from the BM25 [`crate::search::enriched`] /
//! [`crate::search::text`] surfaces. It mirrors the Python reference
//! `tldr/api.py::search` (the grep-shaped `search` subcommand) line-for-line:
//!
//! - **Grep/BRE-habit escape normalization** via [`normalize_grep_pattern`]
//!   (`\|`->`|`, `\(`->`(`, `\)`->`)`, `\d`->`[0-9]`, bracket-class
//!   pass-through, `\\` literal-escape hatch).
//! - **Compile-fallback**: compile the normalized pattern; on failure compile
//!   the *original* pattern (intentional-escape rescue); if that also fails,
//!   propagate the error.
//! - **Single-file mode**: when `root` is a file, skip the directory walk,
//!   ignore rules, `SKIP_DIRS`, and the extension filter (explicit file beats
//!   filter); the `file` field is the basename.
//! - **Directory mode**: walk via `ignore::WalkBuilder` honoring `.gitignore`
//!   + `.tldrignore` (unless `respect_ignore` is false), skip Python-aligned
//!   `SKIP_DIRS`, apply `--exclude-dir` fnmatch per directory component
//!   (independent of ignore — composes with `--no-ignore`), then the
//!   extension filter.
//! - Content is `.trim()`-ed; line numbers are 1-indexed; the `file` field is
//!   root-relative.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use regex::RegexBuilder;

use crate::search::text::SearchMatch;
use crate::TldrResult;

/// Directories skipped during the grep directory walk, aligned to the Python
/// reference `SKIP_DIRS` (`tldr/api.py:268`). Kept independent of the broader
/// `DEFAULT_EXCLUDE_DIRS`/`DEFAULT_SKIP_DIRS` sets so grep stays byte-parity
/// with the Python oracle on which files are scanned.
pub const GREP_SKIP_DIRS: &[&str] = &[
    "node_modules",
    "__pycache__",
    ".git",
    ".svn",
    ".hg",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    ".tox",
    "venv",
    ".venv",
    "env",
    ".env",
    "vendor",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    "egg-info",
    ".eggs",
];

/// Rewrite grep/BRE-habit escapes into the ERE/RE2 the user meant.
///
/// Pure function, no I/O. Left-to-right scan with a bracket-class state
/// machine, ported verbatim from Python `tldr/api.py::normalize_grep_pattern`.
///
/// - Outside a `[...]` class: `\|` -> `|`, `\(` -> `(`, `\)` -> `)`,
///   `\d` -> `[0-9]`. An escaped backslash `\\` is consumed as a pair and
///   emitted verbatim — this is how intentional literal escapes stay
///   reachable (`\\d` matches the literal text `\d`). Every other escape pair
///   (`\.`, `\b`, `\w`, `\s`, `\+`, ...) is emitted verbatim. A trailing lone
///   `\` is emitted verbatim.
/// - Inside a class (entered on an unescaped `[`, honoring a leading `^` and a
///   literal first `]`, exited on `]`): everything, including escape pairs,
///   passes through untouched — prevents `[\d]` -> `[[0-9]]` corruption.
///   Literal metas thus stay reachable via classes: `[|]`, `[(]`, `[)]`.
pub fn normalize_grep_pattern(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(pattern.len());
    let mut i = 0usize;
    let mut in_class = false;
    // index of the first class-content char (used to detect a literal `]`
    // appearing as the first class member).
    let mut class_content_start: isize = -1;

    while i < n {
        let ch = chars[i];
        if in_class {
            if ch == '\\' && i + 1 < n {
                // Escape pair inside a class: pass through untouched.
                out.push(chars[i]);
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            out.push(ch);
            if ch == ']' && (i as isize) > class_content_start {
                in_class = false;
            }
            i += 1;
            continue;
        }
        if ch == '\\' {
            if i + 1 >= n {
                out.push(ch); // trailing lone backslash: verbatim
                i += 1;
                continue;
            }
            let nxt = chars[i + 1];
            match nxt {
                '\\' => out.push_str("\\\\"), // literal-escape escape hatch
                '|' => out.push('|'),
                '(' => out.push('('),
                ')' => out.push(')'),
                'd' => out.push_str("[0-9]"),
                _ => {
                    // same-meaning escape: verbatim
                    out.push(ch);
                    out.push(nxt);
                }
            }
            i += 2;
            continue;
        }
        if ch == '[' {
            in_class = true;
            out.push(ch);
            i += 1;
            if i < n && chars[i] == '^' {
                out.push('^');
                i += 1;
            }
            // A ']' at the content start is a literal, not the terminator.
            class_content_start = i as isize;
            continue;
        }
        out.push(ch);
        i += 1;
    }

    out
}

/// Compile `pattern` with grep-habit normalization and compile-fallback.
///
/// Mirrors Python `re.compile(normalize_grep_pattern(p))` with a fallback to
/// `re.compile(p)`. Returns the compiled [`regex::Regex`], or an error if BOTH
/// the normalized and original patterns fail to compile (the original error is
/// surfaced).
pub fn compile_grep_pattern(pattern: &str, ignore_case: bool) -> Result<regex::Regex, regex::Error> {
    let normalized = normalize_grep_pattern(pattern);
    let build = |p: &str| {
        RegexBuilder::new(p)
            .case_insensitive(ignore_case)
            .build()
    };
    match build(&normalized) {
        Ok(re) => Ok(re),
        Err(_) => build(pattern),
    }
}

/// Search files for a regex pattern (grep-canonical / Python `search` parity).
///
/// # Arguments
/// * `pattern` - Regex pattern (grep/BRE escapes auto-normalized).
/// * `root` - A directory to walk recursively, OR a single file. When a file,
///   `extensions`, ignore rules, `SKIP_DIRS`, and `exclude_dirs` are skipped
///   (explicit file beats filter); the `file` field is the basename.
/// * `extensions` - Optional set of extensions to filter (e.g. `{".py"}`).
///   Ignored in single-file mode.
/// * `context_lines` - Context lines around each match (0 = none).
/// * `max_results` - Cap on total matches (0 = unlimited).
/// * `max_files` - Cap on files scanned (0 = unlimited). Directory mode only.
/// * `ignore_case` - Match case-insensitively.
/// * `exclude_dirs` - `--exclude-dir` globs; a file is skipped when any
///   directory component of its relative path fnmatch-es any glob. Independent
///   of `respect_ignore`. Ignored in single-file mode.
/// * `respect_ignore` - Honor `.gitignore` + `.tldrignore` (directory mode).
/// * `cli_ignore` - Extra gitignore-syntax patterns (`--ignore`), applied as
///   overrides on top of the ignore rules. Ignored when `respect_ignore` is
///   false (matching Python: `--no-ignore` short-circuits the whole spec).
///
/// # Returns
/// * `Ok(Vec<SearchMatch>)` - Matches in walk order.
/// * `Err(TldrError)` - If both normalized and original patterns fail to
///   compile.
#[allow(clippy::too_many_arguments)]
pub fn grep_search(
    pattern: &str,
    root: &Path,
    extensions: Option<&HashSet<String>>,
    context_lines: usize,
    max_results: usize,
    max_files: usize,
    ignore_case: bool,
    exclude_dirs: &[String],
    respect_ignore: bool,
    cli_ignore: &[String],
) -> TldrResult<Vec<SearchMatch>> {
    let compiled = compile_grep_pattern(pattern, ignore_case).map_err(|e| {
        crate::error::TldrError::ParseError {
            file: PathBuf::from("<pattern>"),
            line: None,
            message: format!("Invalid regex: {}", e),
        }
    })?;

    let mut results: Vec<SearchMatch> = Vec::new();

    // Single-file mode: explicit file beats every filter.
    if root.is_file() {
        if let Ok(content) = std::fs::read_to_string(root) {
            let lines: Vec<&str> = content.lines().collect();
            let basename = root
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| root.to_path_buf());
            for (idx, line) in lines.iter().enumerate() {
                if compiled.is_match(line) {
                    let line_no = idx + 1;
                    let context = if context_lines > 0 {
                        Some(slice_context(&lines, idx, context_lines))
                    } else {
                        None
                    };
                    results.push(SearchMatch {
                        file: basename.clone(),
                        line: line_no as u32,
                        content: line.trim().to_string(),
                        context,
                    });
                    if max_results > 0 && results.len() >= max_results {
                        return Ok(results);
                    }
                }
            }
        }
        return Ok(results);
    }

    // Directory mode.
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false) // Python only hides dotfiles in the non-ignore_spec fallback;
        // gitignore/.tldrignore handles real hiding. We additionally drop
        // GREP_SKIP_DIRS below.
        .git_ignore(respect_ignore)
        .git_global(respect_ignore)
        .git_exclude(respect_ignore)
        .parents(respect_ignore)
        .follow_links(false);
    // .tldrignore as a custom per-directory ignore file (gitignore syntax).
    if respect_ignore {
        builder.add_custom_ignore_filename(".tldrignore");
        if !cli_ignore.is_empty() {
            let mut ov = ignore::overrides::OverrideBuilder::new(root);
            for pat in cli_ignore {
                // `--ignore PATTERN` excludes matching paths. In gitignore
                // override syntax an un-prefixed glob is an *allow*; a `!`
                // prefix is an *ignore*. So negate to turn it into an
                // exclusion.
                let _ = ov.add(&format!("!{}", pat));
            }
            if let Ok(over) = ov.build() {
                builder.overrides(over);
            }
        }
    }

    let mut files_scanned = 0usize;

    for entry in builder.build() {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        if max_files > 0 && files_scanned >= max_files {
            break;
        }

        let rel = match path.strip_prefix(root) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let parts: Vec<&std::ffi::OsStr> = rel.iter().collect();

        // GREP_SKIP_DIRS: skip files under any junk directory component. This
        // is applied uniformly (Python applies it only in the non-ignore_spec
        // fallback, but vendor/build/etc. are also in .gitignore-style sets;
        // applying uniformly matches the documented spec decision to ALIGN to
        // the Python SKIP_DIRS set).
        let in_skip_dir = parts[..parts.len().saturating_sub(1)]
            .iter()
            .any(|c| c.to_str().map(|s| GREP_SKIP_DIRS.contains(&s)).unwrap_or(false));
        if in_skip_dir {
            continue;
        }

        // grep --exclude-dir: fnmatch any directory component against any glob,
        // independent of ignore (composes with --no-ignore).
        if !exclude_dirs.is_empty() {
            let excluded = parts[..parts.len().saturating_sub(1)].iter().any(|c| {
                c.to_str().map_or(false, |comp| {
                    exclude_dirs.iter().any(|pat| {
                        glob::Pattern::new(pat)
                            .map(|p| p.matches(comp))
                            .unwrap_or(false)
                    })
                })
            });
            if excluded {
                continue;
            }
        }

        // Extension filter.
        if let Some(exts) = extensions {
            let suffix = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{}", e))
                .unwrap_or_default();
            if !exts.contains(&suffix) {
                continue;
            }
        }

        files_scanned += 1;

        if let Ok(content) = std::fs::read_to_string(path) {
            let lines: Vec<&str> = content.lines().collect();
            for (idx, line) in lines.iter().enumerate() {
                if compiled.is_match(line) {
                    let line_no = idx + 1;
                    let context = if context_lines > 0 {
                        Some(slice_context(&lines, idx, context_lines))
                    } else {
                        None
                    };
                    results.push(SearchMatch {
                        file: rel.to_path_buf(),
                        line: line_no as u32,
                        content: line.trim().to_string(),
                        context,
                    });
                    if max_results > 0 && results.len() >= max_results {
                        return Ok(results);
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Slice `[start..end]` context lines around a 0-based match index, matching
/// Python `lines[max(0, i-1-ctx) : min(len, i+ctx)]` where `i` is 1-based.
fn slice_context(lines: &[&str], match_idx0: usize, context_lines: usize) -> Vec<String> {
    let i1 = match_idx0 + 1; // 1-based line number
    let start = i1.saturating_sub(1 + context_lines);
    let end = (i1 + context_lines).min(lines.len());
    lines[start..end].iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tempfile::TempDir;

    fn exts(list: &[&str]) -> HashSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn normalize_table() {
        // Verified against Python normalize_grep_pattern / live oracle.
        let cases: &[(&str, &str)] = &[
            (r"foo\|bar", "foo|bar"),
            (r"foo|bar", "foo|bar"),
            (r"\d+", "[0-9]+"),
            (r"[\d]", r"[\d]"),
            (r"\\d", r"\\d"),
            (r"[|]", "[|]"),
            (r"foo\(", "foo("),
            (r"foo\)", "foo)"),
            (r"\.", r"\."),
            (r"\w+", r"\w+"),
            (r"a\\", r"a\\"),
            (r"[^\d]", r"[^\d]"),
            (r"[]a]", "[]a]"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                normalize_grep_pattern(input),
                *expected,
                "normalize({:?})",
                input
            );
        }
    }

    #[test]
    fn d_is_ascii_only() {
        // \d -> [0-9] narrows to ASCII; a non-ASCII digit must NOT match.
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.txt"), "123\n٤٥٦\n").unwrap();
        let hits = grep_search(
            r"\d",
            &dir.path().join("a.txt"),
            None,
            0,
            0,
            0,
            false,
            &[],
            true,
            &[],
        )
        .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 1);
    }

    #[test]
    fn single_file_basename_and_trim() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("indent.py");
        std::fs::write(&f, "    indented = 1\n").unwrap();
        let hits = grep_search(
            "indented", &f, None, 0, 0, 0, false, &[], true, &[],
        )
        .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].file, PathBuf::from("indent.py"));
        assert_eq!(hits[0].content, "indented = 1"); // trimmed
        assert_eq!(hits[0].line, 1);
    }

    #[test]
    fn single_file_ignores_include() {
        // Single-file mode skips the extension filter (explicit beats filter).
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("notes.txt");
        std::fs::write(&f, "TODO here\n").unwrap();
        let hits = grep_search(
            "TODO",
            &f,
            Some(&exts(&[".py"])), // would exclude .txt in dir mode
            0,
            0,
            0,
            false,
            &[],
            true,
            &[],
        )
        .unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn ignore_case_flag() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("n.txt");
        std::fs::write(&f, "TODO one\ntodo two\n").unwrap();
        let ci = grep_search("todo", &f, None, 0, 0, 0, true, &[], true, &[]).unwrap();
        assert_eq!(ci.len(), 2);
        let cs = grep_search("todo", &f, None, 0, 0, 0, false, &[], true, &[]).unwrap();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].line, 2);
    }

    #[test]
    fn invalid_regex_errors() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, "x\n").unwrap();
        // 'foo(' normalizes to 'foo(' (no \( ) which is an unbalanced paren;
        // original 'foo(' also fails -> error.
        let res = grep_search("foo(", &f, None, 0, 0, 0, false, &[], true, &[]);
        assert!(res.is_err());
    }

    #[test]
    fn compile_fallback_to_original() {
        // 'foo\(' normalizes to 'foo(' which fails to compile; fallback to the
        // original 'foo\(' (literal paren) succeeds.
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, "def foo(): pass\n").unwrap();
        let hits = grep_search(r"foo\(", &f, None, 0, 0, 0, false, &[], true, &[]).unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn exclude_dir_skip() {
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
            false, // no ignore so we don't need a git repo
            &[],
        )
        .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].file, PathBuf::from("lib/b.py"));
    }

    #[test]
    fn ext_filter() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.py"), "TODO\n").unwrap();
        std::fs::write(dir.path().join("b.txt"), "TODO\n").unwrap();
        let hits = grep_search(
            "TODO",
            dir.path(),
            Some(&exts(&[".py"])),
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
        assert_eq!(hits[0].file, PathBuf::from("a.py"));
    }

    #[test]
    fn max_results_cap() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, "foo\nfoo\nfoo\n").unwrap();
        let hits = grep_search("foo", &f, None, 0, 1, 0, false, &[], true, &[]).unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn skip_dirs_vendor() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("vendor")).unwrap();
        std::fs::write(dir.path().join("vendor/v.py"), "TODO\n").unwrap();
        std::fs::write(dir.path().join("keep.py"), "TODO\n").unwrap();
        // Even with no ignore, vendor/ is in GREP_SKIP_DIRS.
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
    fn gitignore_and_tldrignore() {
        let dir = TempDir::new().unwrap();
        // Make it a git repo so .gitignore is honored.
        std::process::Command::new("git")
            .arg("init")
            .arg("-q")
            .current_dir(dir.path())
            .status()
            .unwrap();
        std::fs::write(dir.path().join(".gitignore"), "ignored_by_git/\n").unwrap();
        std::fs::write(dir.path().join(".tldrignore"), "skipme/\n").unwrap();
        std::fs::create_dir_all(dir.path().join("ignored_by_git")).unwrap();
        std::fs::create_dir_all(dir.path().join("skipme")).unwrap();
        std::fs::create_dir_all(dir.path().join("keep")).unwrap();
        std::fs::write(dir.path().join("ignored_by_git/g.py"), "TODO\n").unwrap();
        std::fs::write(dir.path().join("skipme/s.py"), "TODO\n").unwrap();
        std::fs::write(dir.path().join("keep/a.py"), "TODO\n").unwrap();

        let hits = grep_search(
            "TODO",
            dir.path(),
            None,
            0,
            0,
            0,
            false,
            &[],
            true, // respect ignore
            &[],
        )
        .unwrap();
        let files: HashSet<_> = hits.iter().map(|h| h.file.clone()).collect();
        assert!(files.contains(&PathBuf::from("keep/a.py")), "keep/a.py present");
        assert!(
            !files.contains(&PathBuf::from("skipme/s.py")),
            ".tldrignore honored"
        );
        assert!(
            !files.contains(&PathBuf::from("ignored_by_git/g.py")),
            ".gitignore honored"
        );

        // With --no-ignore the .tldrignore'd dir reappears (but not git-ignored,
        // since no_ignore disables the whole spec in Python too).
        let hits2 = grep_search(
            "TODO",
            dir.path(),
            None,
            0,
            0,
            0,
            false,
            &[],
            false, // no ignore
            &[],
        )
        .unwrap();
        let files2: HashSet<_> = hits2.iter().map(|h| h.file.clone()).collect();
        assert!(files2.contains(&PathBuf::from("skipme/s.py")), "no-ignore reveals skipme");
    }

    #[test]
    fn context_lines() {
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
}
