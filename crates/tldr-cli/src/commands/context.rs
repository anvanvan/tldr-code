//! Context command - Build LLM context
//!
//! Generates token-efficient LLM context from one or more entry points.
//! Auto-routes through daemon when available for ~35x speedup (single-symbol
//! path only).
//!
//! context-batch (Python parity, area 4): `entry` is variadic — a single
//! symbol takes the legacy path (hit → stdout, miss → `Err` → exit 20), while
//! N symbols take a per-symbol probe path (hits → stdout blank-line-separated,
//! misses → stderr per-line, exit non-zero only when ALL miss). `--lang` now
//! accepts `auto` (default) / `all` / an explicit language.

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;

use tldr_core::context::resolve::{
    get_relevant_context_multi, resolve_context_languages, MultiContextOutcome,
};
use tldr_core::types::RelevantContext as TypesRelevantContext;
use tldr_core::{get_relevant_context, Language};

use crate::commands::daemon_router::{params_with_entry_depth, try_daemon_route};
use crate::output::{OutputFormat, OutputWriter};

/// Build LLM-ready context from one or more entry points.
#[derive(Debug, Args)]
pub struct ContextArgs {
    /// Entry point function name(s). One symbol → legacy single-context
    /// output; two or more → one context block per symbol (batch mode).
    ///
    /// context-batch: `num_args = 1..` makes this variadic. A trailing
    /// positional that resolves to an existing directory is interpreted as
    /// the project root (back-compat with `tldr context foo .`) unless
    /// `--project` was supplied.
    #[arg(num_args = 1.., required = true)]
    pub entry: Vec<String>,

    /// Project root directory (alias for a trailing positional path; mirrors
    /// sibling path-taking commands). When set, this takes precedence over a
    /// trailing positional path and disables the directory-pop heuristic.
    #[arg(long, short = 'p')]
    pub project: Option<PathBuf>,

    // Language selection (`auto` / `all` / explicit) comes from the GLOBAL
    // `--lang`/`-l` flag. clap merges any context-local `lang` arg with the
    // global one by id (same `--lang`/`-l`), so a per-command field of a
    // different type panics at runtime. Instead `main.rs` resolves the global
    // selector into a token string and threads it into `run` (the global
    // parser accepts the `auto` / `all` tokens). (context-batch)
    /// Maximum traversal depth (Python parity default: 2).
    #[arg(long, short = 'd', default_value = "2")]
    pub depth: usize,

    /// Include function docstrings
    #[arg(long)]
    pub include_docstrings: bool,

    /// Filter to functions in this file (for disambiguating common names like "render")
    #[arg(long)]
    pub file: Option<PathBuf>,
}

impl ContextArgs {
    /// Split the variadic positionals into `(symbols, project_path)`.
    ///
    /// Resolution (context-batch clap-ambiguity decision):
    /// - If `--project` is set, all positionals are symbols and the project is
    ///   the explicit flag value.
    /// - Otherwise, if there are ≥2 positionals AND the last one resolves to an
    ///   existing directory, it is popped as the project root (back-compat with
    ///   `tldr context foo .`). The remaining positionals are the symbols.
    /// - Otherwise the project defaults to `.` and every positional is a symbol.
    fn split_entries_and_path(&self) -> (Vec<String>, PathBuf) {
        if let Some(p) = &self.project {
            return (self.entry.clone(), p.clone());
        }
        let mut symbols = self.entry.clone();
        if symbols.len() >= 2 {
            if let Some(last) = symbols.last() {
                if Path::new(last).is_dir() {
                    let path = PathBuf::from(symbols.pop().unwrap());
                    return (symbols, path);
                }
            }
        }
        (symbols, PathBuf::from("."))
    }

    /// Run the context command.
    ///
    /// `lang_token` is the global `--lang` selector resolved by `main.rs`
    /// (`"auto"` / `"all"` / a language name; defaulted to `"auto"`).
    pub fn run(&self, format: OutputFormat, quiet: bool, lang_token: &str) -> Result<()> {
        let (symbols, project_path) = self.split_entries_and_path();

        if symbols.len() == 1 {
            self.run_single(&symbols[0], &project_path, format, quiet, lang_token)
        } else {
            self.run_batch(&symbols, &project_path, format, quiet, lang_token)
        }
    }

    /// Single-symbol legacy path: keeps the `<file>:<func>` shorthand + daemon
    /// route, and bubbles a miss as `Err` (exit 20 — unchanged).
    fn run_single(
        &self,
        symbol: &str,
        project_root: &Path,
        format: OutputFormat,
        quiet: bool,
        lang_token: &str,
    ) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);
        let mut project_path = project_root.to_path_buf();

        // Accept the `<file>:<func>` shorthand (mirrors `tldr explain`/
        // `tldr resources`). Walk colons RIGHT-TO-LEFT, picking the leftmost
        // split whose file_part exists on disk (so C++ `Class::method` and
        // Windows drive letters keep working).
        let (entry, derived_file): (String, Option<PathBuf>) =
            match split_file_func_shorthand(symbol) {
                Some((file, func)) => (func, Some(file)),
                None => (symbol.to_string(), None),
            };

        // Explicit --file wins over the derived form.
        let effective_file: Option<PathBuf> = self.file.clone().or_else(|| derived_file.clone());

        // Auto-derive project root from the file when the shorthand was used
        // and no explicit project was supplied.
        if derived_file.is_some() && self.project.is_none() && project_path == PathBuf::from(".") {
            if let Some(file) = effective_file.as_ref() {
                if let Some(root) = infer_project_root_from_file(file) {
                    project_path = root;
                }
            }
        }

        // Resolve the language list to probe.
        let languages =
            resolve_context_languages(lang_token, &project_path).map_err(|e| anyhow::anyhow!(e))?;

        // Try daemon first (single path only, and only when there is no
        // derived-file disambiguation — the daemon protocol does not propagate
        // the `--file` filter).
        if effective_file.is_none() {
            if let Some(context) = try_daemon_route::<TypesRelevantContext>(
                &project_path,
                "context",
                params_with_entry_depth(&entry, Some(self.depth)),
            ) {
                if writer.is_text() {
                    writer.write_text(&context.to_llm_string())?;
                } else {
                    writer.write(&context)?;
                }
                return Ok(());
            }
        }

        writer.progress(&format!(
            "Building context for {} (depth={})...",
            entry, self.depth
        ));

        // When a file filter is in play we must use the single-language
        // `get_relevant_context` (the multi probe does not thread the filter).
        if let Some(file) = effective_file.as_deref() {
            let primary = languages.first().copied().unwrap_or(Language::Python);
            let context = get_relevant_context(
                &project_path,
                &entry,
                self.depth,
                primary,
                self.include_docstrings,
                Some(file),
            )?;
            if writer.is_text() {
                writer.write_text(&context.to_llm_string())?;
            } else {
                writer.write(&context)?;
            }
            return Ok(());
        }

        // No file filter: probe the resolved language list, first hit wins.
        match get_relevant_context_multi(
            &project_path,
            &entry,
            self.depth,
            &languages,
            self.include_docstrings,
        ) {
            MultiContextOutcome::Hit(context) => {
                if writer.is_text() {
                    writer.write_text(&context.to_llm_string())?;
                } else {
                    writer.write(context.as_ref())?;
                }
                Ok(())
            }
            // Miss → bubble FunctionNotFound (exit 20 — unchanged). The
            // suggestions ride along so the `Did you mean` line is rendered.
            miss => {
                let suggestions = match &miss {
                    MultiContextOutcome::Miss { suggestions, .. } => suggestions.clone(),
                    _ => Vec::new(),
                };
                Err(tldr_core::TldrError::function_not_found_with_suggestions(
                    entry.clone(),
                    None,
                    suggestions,
                )
                .into())
            }
        }
    }

    /// Batch path: per-symbol probe; hits → stdout (blank-line-separated),
    /// misses → stderr per-line. Exit non-zero only when ALL miss.
    fn run_batch(
        &self,
        symbols: &[String],
        project_root: &Path,
        format: OutputFormat,
        quiet: bool,
        lang_token: &str,
    ) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);
        let languages =
            resolve_context_languages(lang_token, project_root).map_err(|e| anyhow::anyhow!(e))?;

        let mut any_resolved = false;
        for symbol in symbols {
            let outcome = get_relevant_context_multi(
                project_root,
                symbol,
                self.depth,
                &languages,
                self.include_docstrings,
            );
            match outcome {
                MultiContextOutcome::Hit(context) => {
                    if writer.is_text() {
                        // One blank line BETWEEN blocks (matches Python).
                        if any_resolved {
                            println!();
                        }
                        writer.write_text(&context.to_llm_string())?;
                    } else {
                        writer.write(context.as_ref())?;
                    }
                    any_resolved = true;
                }
                miss @ MultiContextOutcome::Miss { .. } => {
                    if let Some(msg) = miss.miss_message() {
                        eprintln!("Error: {}", msg);
                    }
                }
            }
        }

        if !any_resolved {
            // All symbols missed → non-zero exit. Reuse FunctionNotFound so the
            // CLI maps it to the analysis exit code (20); per-symbol messages
            // were already written to stderr above.
            return Err(tldr_core::TldrError::function_not_found(symbols.join(", ")).into());
        }
        Ok(())
    }
}

/// Parse the `<file>:<func>` shorthand argument into a `(file_path,
/// func_name)` pair, walking colons right-to-left to find the leftmost
/// split point whose file_part exists on disk.
fn split_file_func_shorthand(entry: &str) -> Option<(PathBuf, String)> {
    let mut idx = entry.rfind(':')?;
    loop {
        if idx == 0 || idx + 1 >= entry.len() {
            match entry[..idx].rfind(':') {
                Some(prev) => {
                    idx = prev;
                    continue;
                }
                None => return None,
            }
        }
        let file_part = &entry[..idx];
        let func_part = &entry[idx + 1..];
        let candidate = PathBuf::from(file_part);
        if candidate.is_file() && !func_part.is_empty() && !func_part.starts_with(':') {
            return Some((candidate, func_part.to_string()));
        }
        match entry[..idx].rfind(':') {
            Some(prev) => idx = prev,
            None => return None,
        }
    }
}

/// Walk upward from `file`'s parent directory until we hit a directory
/// containing one of the common project-root markers. Returns
/// `Some(parent_dir)` as a fallback if no marker is found.
fn infer_project_root_from_file(file: &Path) -> Option<PathBuf> {
    let abs = file.canonicalize().unwrap_or_else(|_| file.to_path_buf());
    let parent = abs.parent()?;
    const MARKERS: &[&str] = &[
        ".git",
        "package.json",
        "Cargo.toml",
        "go.mod",
        "pyproject.toml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "mix.exs",
        "dune-project",
        "Package.swift",
    ];
    let mut cursor: Option<&Path> = Some(parent);
    while let Some(dir) = cursor {
        for m in MARKERS {
            if dir.join(m).exists() {
                return Some(dir.to_path_buf());
            }
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if entry
                    .path()
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e == "csproj" || e == "sln")
                    .unwrap_or(false)
                {
                    return Some(dir.to_path_buf());
                }
            }
        }
        cursor = dir.parent();
    }
    Some(parent.to_path_buf())
}
