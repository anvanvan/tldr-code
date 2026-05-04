//! Context command - Build LLM context
//!
//! Generates token-efficient LLM context from an entry point.
//! Auto-routes through daemon when available for ~35x speedup.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::types::RelevantContext;
use tldr_core::{get_relevant_context, Language};

use crate::commands::daemon_router::{params_with_entry_depth, try_daemon_route};
use crate::output::{OutputFormat, OutputWriter};

/// Build LLM-ready context from entry point
#[derive(Debug, Args)]
pub struct ContextArgs {
    /// Entry point function name
    pub entry: String,

    /// Project root directory as positional argument (mirrors sibling
    /// path-taking commands like `impact`, `whatbreaks`). When set, this
    /// takes precedence over `--project`. (med-cleanup-bundle-v1 / M1)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Project root directory (deprecated alias for the positional path
    /// argument; kept for back-compat). (med-cleanup-bundle-v1 / M1)
    #[arg(long, short = 'p')]
    pub project: Option<PathBuf>,

    /// Programming language
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Maximum traversal depth
    #[arg(long, short = 'd', default_value = "3")]
    pub depth: usize,

    /// Include function docstrings
    #[arg(long)]
    pub include_docstrings: bool,

    /// Filter to functions in this file (for disambiguating common names like "render")
    #[arg(long)]
    pub file: Option<PathBuf>,
}

impl ContextArgs {
    /// Resolve the effective project path. The positional `path` argument
    /// is the canonical input; `--project` is kept as a back-compat alias
    /// and only wins when the positional path is left at its default ".".
    /// (med-cleanup-bundle-v1 / M1)
    fn effective_project(&self) -> PathBuf {
        match &self.project {
            Some(p) if self.path == PathBuf::from(".") => p.clone(),
            _ => self.path.clone(),
        }
    }

    /// Run the context command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        let project_path = self.effective_project();

        // Determine language (auto-detect from directory, default to Python)
        let language = self
            .lang
            .unwrap_or_else(|| Language::from_directory(&project_path).unwrap_or(Language::Python));

        // Try daemon first for cached result
        if let Some(context) = try_daemon_route::<RelevantContext>(
            &project_path,
            "context",
            params_with_entry_depth(&self.entry, Some(self.depth)),
        ) {
            // Output based on format
            if writer.is_text() {
                // Use the built-in LLM string format
                let text = context.to_llm_string();
                writer.write_text(&text)?;
                return Ok(());
            } else {
                writer.write(&context)?;
                return Ok(());
            }
        }

        // Fallback to direct compute
        writer.progress(&format!(
            "Building context for {} (depth={})...",
            self.entry, self.depth
        ));

        // Get relevant context
        let context = get_relevant_context(
            &project_path,
            &self.entry,
            self.depth,
            language,
            self.include_docstrings,
            self.file.as_deref(),
        )?;

        // Output based on format
        if writer.is_text() {
            // Use the built-in LLM string format
            let text = context.to_llm_string();
            writer.write_text(&text)?;
        } else {
            writer.write(&context)?;
        }

        Ok(())
    }
}
