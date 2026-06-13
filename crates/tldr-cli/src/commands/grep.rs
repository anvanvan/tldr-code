//! Grep command - line-oriented regex search (Python `tldr search` parity).
//!
//! This is a distinct command from the BM25 `search` command. It mirrors the
//! Python reference `tldr search` (the grep-shaped subcommand) and emits a
//! flat JSON array of `{file, line, content}` objects.
//!
//! Behaviors (all parity-verified against the Python oracle):
//! - Grep/BRE-habit escape normalization (`\|`->`|`, `\d`->`[0-9]`, ...) +
//!   compile-fallback to the original pattern.
//! - `-i`/`--ignore-case` (case-sensitive default).
//! - Repeatable `--include` glob -> extension filter (bad glob -> exit 2).
//! - Repeatable `--exclude-dir` fnmatch per directory component.
//! - Multiple path positionals, merged in path order, with `-m` budget
//!   spanning paths and multi-path file-prefix rewrite rules.
//! - Single-file mode (basename file, trimmed content).
//! - Missing path -> exit 1 `Error: path '<p>' not found`.
//! - Zero hits -> `[]` exit 0.
//! - Honors `.gitignore` + `.tldrignore` unless `--no-ignore`; `--ignore`
//!   adds extra patterns.
//!
//! NOT daemon-routed (Python parity).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use tldr_core::{grep_search, SearchMatch};

use crate::output::{format_search_text, OutputFormat, OutputWriter};

/// A single flat grep hit (`{file, line, content}`), matching the Python
/// reference output schema. `context` is emitted only when `-C`/`--context`
/// is non-zero.
#[derive(Debug, Serialize)]
pub struct GrepHit {
    /// File path (root-relative for dir args; basename for single-file; the
    /// path argument itself when a file is named in multi-path mode).
    pub file: String,
    /// 1-indexed line number.
    pub line: u32,
    /// The matching line, trimmed.
    pub content: String,
    /// Context lines around the match (only when `-C` > 0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<String>>,
}

/// Grep: line-oriented regex search emitting a flat `[{file,line,content}]`
/// array.
///
/// Grep/BRE-habit escapes (`\|`, `\(`, `\)`, `\d`) are auto-normalized to
/// their ERE meaning. Use a character class for a literal meta (`[|]`,
/// `[(]`) and `\\d` for a literal `\d`.
#[derive(Debug, Args)]
pub struct GrepArgs {
    /// Regex pattern to search for.
    pub pattern: String,

    /// Directories or files to search (default: current directory). Multiple
    /// paths are merged in order.
    #[arg(default_value = ".")]
    pub path: Vec<PathBuf>,

    /// Match case-insensitively.
    #[arg(short = 'i', long = "ignore-case")]
    pub ignore_case: bool,

    /// File filter: `*.py` or `.py` or `py` (repeatable).
    #[arg(long = "include", value_name = "GLOB")]
    pub include: Vec<String>,

    /// Skip files under any directory component matching GLOB (repeatable).
    #[arg(long = "exclude-dir", value_name = "GLOB")]
    pub exclude_dir: Vec<String>,

    /// Context lines around each match.
    #[arg(short = 'C', long = "context", default_value = "0")]
    pub context: usize,

    /// Max total results (default: 100, 0 = unlimited).
    #[arg(short = 'm', long = "max-count", default_value = "100")]
    pub max_count: usize,

    /// Max files to scan (default: 10000, 0 = unlimited).
    #[arg(long = "max-files", default_value = "10000")]
    pub max_files: usize,

    /// Disable `.gitignore` / `.tldrignore` (grep-scoped).
    #[arg(long = "no-ignore")]
    pub no_ignore: bool,

    /// Additional gitignore-syntax patterns to exclude (repeatable,
    /// grep-scoped).
    #[arg(long = "ignore", value_name = "PATTERN")]
    pub ignore: Vec<String>,
}

/// Map `--include` glob values onto an extension-filter set.
///
/// Supported shapes (case preserved): `*.py` -> `.py`; `.py` -> `.py`;
/// `py` -> `.py`. Empty -> `None` (no filter). Any other shape is a hard
/// error (caller exits 2), mirroring Python `_includes_to_extensions`.
pub fn includes_to_extensions(includes: &[String]) -> Result<Option<HashSet<String>>, String> {
    if includes.is_empty() {
        return Ok(None);
    }
    let mut extensions = HashSet::new();
    for glob in includes {
        let suffix: Option<&str> = if !glob.contains('/') && !glob.contains('\\') {
            if let Some(rest) = glob.strip_prefix("*.") {
                Some(rest)
            } else if let Some(rest) = glob.strip_prefix('.') {
                Some(rest)
            } else {
                Some(glob.as_str())
            }
        } else {
            None
        };
        let bad = match suffix {
            None => true,
            Some(s) => s.is_empty() || s.chars().any(|c| "*?[]./\\".contains(c)),
        };
        if bad {
            return Err(format!(
                "unsupported --include glob '{}'; use '*.EXT' or '.EXT'",
                glob
            ));
        }
        extensions.insert(format!(".{}", suffix.unwrap()));
    }
    Ok(Some(extensions))
}

impl GrepArgs {
    /// Run the grep command.
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        let paths: Vec<PathBuf> = if self.path.is_empty() {
            vec![PathBuf::from(".")]
        } else {
            self.path.clone()
        };

        // Validate ALL paths before searching any (Python: exit 1).
        for p in &paths {
            if !p.exists() {
                anyhow::bail!("path '{}' not found", p.display());
            }
        }

        // --include glob -> extension set (bad glob -> exit 2).
        let extensions = match includes_to_extensions(&self.include) {
            Ok(e) => e,
            Err(msg) => {
                eprintln!("{}", msg);
                std::process::exit(2);
            }
        };

        let respect_ignore = !self.no_ignore;
        let multi_path = paths.len() > 1;

        let mut hits: Vec<GrepHit> = Vec::new();
        let mut all_matches: Vec<SearchMatch> = Vec::new();

        for p in &paths {
            // -m budget spans paths: each path gets the remainder.
            let budget = if self.max_count == 0 {
                0
            } else {
                self.max_count.saturating_sub(hits.len())
            };
            if self.max_count > 0 && budget == 0 {
                break;
            }

            let is_file = p.is_file();

            let matches = grep_search(
                &self.pattern,
                p,
                extensions.as_ref(),
                self.context,
                budget,
                self.max_files,
                self.ignore_case,
                &self.exclude_dir,
                respect_ignore,
                &self.ignore,
            )?;

            for m in matches {
                // Path-prefix rules:
                // - single dir/file path: use the engine's `file` verbatim
                //   (basename for single-file, root-relative for dir).
                // - multi-path: a file arg's identity IS the path argument;
                //   a dir arg gets `join(p, rel)`.
                let file = if multi_path {
                    if is_file {
                        p.to_string_lossy().to_string()
                    } else {
                        join_display(p, &m.file)
                    }
                } else {
                    m.file.to_string_lossy().to_string()
                };
                hits.push(GrepHit {
                    file,
                    line: m.line,
                    content: m.content.clone(),
                    context: m.context.clone(),
                });
                all_matches.push(m);
            }
        }

        if writer.is_text() {
            // Reuse the existing search text formatter (which trims content).
            // Rebuild SearchMatch with the prefixed file paths so the text
            // view agrees with the JSON identity.
            let prefixed: Vec<SearchMatch> = hits
                .iter()
                .map(|h| SearchMatch {
                    file: PathBuf::from(&h.file),
                    line: h.line,
                    content: h.content.clone(),
                    context: h.context.clone(),
                })
                .collect();
            let text = format_search_text(&prefixed);
            writer.write_text(&text)?;
        } else {
            // Flat array, even when empty (Python emits `[]`).
            writer.write(&hits)?;
        }

        Ok(())
    }
}

/// Join a path argument with a root-relative match path for display, using
/// forward-slash semantics that match Python's `os.path.join(p, rel)`.
fn join_display(arg: &Path, rel: &Path) -> String {
    arg.join(rel).to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn includes_basic_shapes() {
        let got = includes_to_extensions(&[
            "*.py".to_string(),
            ".txt".to_string(),
            "rs".to_string(),
        ])
        .unwrap()
        .unwrap();
        assert!(got.contains(".py"));
        assert!(got.contains(".txt"));
        assert!(got.contains(".rs"));
    }

    #[test]
    fn includes_empty_is_none() {
        assert!(includes_to_extensions(&[]).unwrap().is_none());
    }

    #[test]
    fn includes_bad_glob_errors() {
        assert!(includes_to_extensions(&["[".to_string()]).is_err());
        assert!(includes_to_extensions(&["*.t.x".to_string()]).is_err());
        assert!(includes_to_extensions(&["a/b".to_string()]).is_err());
        assert!(includes_to_extensions(&["*".to_string()]).is_err());
    }
}
