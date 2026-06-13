//! Semantic command - Semantic code search
//!
//! Performs natural language search over code using dense embeddings.
//! Builds an in-memory index and returns semantically similar code chunks.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::semantic::{
    BuildOptions, CacheConfig, ChunkGranularity, Device, EmbeddingModel, IndexSearchOptions,
    SemanticIndex,
};

use crate::output::{OutputFormat, OutputWriter};

/// Semantic code search using embeddings
#[derive(Debug, Args)]
pub struct SemanticArgs {
    /// Natural language query
    pub query: String,

    /// Project root (positional; overrides `--path`). Default: current directory.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Project root (Python-parity alias of the positional PATH). The
    /// positional PATH overrides this when both are given.
    #[arg(long = "path", value_name = "PATH")]
    pub path_flag: Option<PathBuf>,

    /// Maximum number of results
    #[arg(short = 'n', long, default_value = "10")]
    pub top: usize,

    /// Number of results (Python-parity alias of `-n`/`--top`). When set,
    /// `--k` takes precedence over `--top` (`effective_k = k.unwrap_or(top)`).
    #[arg(long = "k", value_name = "N")]
    pub k: Option<usize>,

    /// Include call-graph expansion (`calls`/`called_by`/`related`) per result.
    #[arg(long)]
    pub expand: bool,

    /// Compute device: `cpu` or `gpu`. Omitted => `TLDR_DEVICE` env, else `gpu`.
    ///
    /// DEVIATION from Python (which defaults to `cpu` and labels the GPU path
    /// `metal`): the default here is `gpu` (per explicit user override), which
    /// resolves to CoreML on Apple Silicon when built with the `coreml` feature
    /// and transparently falls back to CPU otherwise. `metal` is accepted as an
    /// alias of `gpu` for Python back-compat.
    #[arg(long, value_name = "DEVICE")]
    pub device: Option<String>,

    /// Minimum similarity threshold (0.0 to 1.0)
    #[arg(short = 't', long, default_value = "0.5")]
    pub threshold: f64,

    /// Embedding model: arctic-xs, arctic-s, arctic-m, arctic-m-long, arctic-l
    #[arg(short, long, default_value = "arctic-m")]
    pub model: String,

    /// Filter by language via file extensions (comma-separated, e.g., `--langs rs,py`).
    ///
    /// Values are parsed by `Language::from_extension`, which accepts file
    /// extensions such as `rs`, `py`, `ts`, `go`, `java`, `rb`, `kt`, `cpp`.
    /// Language names (`rust`, `python`) are NOT accepted here; use the
    /// global `--lang <LANG>` flag above for name-based single-language
    /// selection. Passing an unknown extension silently drops that entry
    /// from the filter.
    ///
    /// Renamed from `--lang` (pre-VAL-009) to avoid a clap TypeId collision
    /// with the global `--lang` arg which is `Option<Language>`.
    #[arg(long = "langs", value_delimiter = ',')]
    pub langs: Option<Vec<String>>,

    /// Disable embedding cache
    #[arg(long)]
    pub no_cache: bool,
}

impl SemanticArgs {
    /// Resolve the project root: positional PATH wins over `--path`.
    ///
    /// The positional `path` has a clap default of `.`; when the user passed
    /// neither a positional path nor `--path`, this is `.`. When only `--path`
    /// is given (positional left at default `.`), `--path` is used.
    pub fn resolved_path(&self) -> PathBuf {
        // The positional default is ".". If the positional is the default and a
        // --path flag was supplied, prefer the flag; otherwise the positional
        // (which the user may have set explicitly) wins.
        if self.path == PathBuf::from(".") {
            if let Some(ref p) = self.path_flag {
                return p.clone();
            }
        }
        self.path.clone()
    }

    /// Effective result count: `--k` overrides `-n`/`--top` when present.
    pub fn effective_k(&self) -> usize {
        self.k.unwrap_or(self.top)
    }

    /// Run the semantic search command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Parse model
        let model = parse_model(&self.model)?;

        // Resolve compute device: flag > TLDR_DEVICE env > Gpu default.
        let device = Device::resolve(self.device.as_deref()).map_err(|e| anyhow::anyhow!(e))?;

        let root = self.resolved_path();

        writer.progress(&format!(
            "Building semantic index for {} ({} model, device={})...",
            root.display(),
            self.model,
            device.as_str(),
        ));

        // Build options
        let build_opts = BuildOptions {
            model,
            granularity: ChunkGranularity::Function,
            languages: self.langs.clone(),
            show_progress: !quiet,
            use_cache: !self.no_cache,
            device,
        };

        // Cache config
        let cache_config = if self.no_cache {
            None
        } else {
            Some(CacheConfig::default())
        };

        // Build index
        let mut index = SemanticIndex::build(&root, build_opts, cache_config)?;

        writer.progress(&format!(
            "Searching {} chunks for '{}'...",
            index.len(),
            self.query
        ));

        // Search options
        let search_opts = IndexSearchOptions {
            top_k: self.effective_k(),
            threshold: self.threshold,
            include_snippet: true,
            snippet_lines: 5,
            expand: self.expand,
        };

        // Perform search
        let report = index.search(&self.query, &search_opts)?;

        // Output based on format
        if writer.is_text() {
            let text = format_semantic_text(&report);
            writer.write_text(&text)?;
        } else {
            writer.write(&report)?;
        }

        Ok(())
    }
}

/// Parse model string into EmbeddingModel
fn parse_model(model_str: &str) -> Result<EmbeddingModel> {
    match model_str {
        "arctic-xs" | "xs" => Ok(EmbeddingModel::ArcticXS),
        "arctic-s" | "s" => Ok(EmbeddingModel::ArcticS),
        "arctic-m" | "m" => Ok(EmbeddingModel::ArcticM),
        "arctic-m-long" | "m-long" => Ok(EmbeddingModel::ArcticMLong),
        "arctic-l" | "l" => Ok(EmbeddingModel::ArcticL),
        _ => Err(anyhow::anyhow!(
            "Invalid model '{}'. Options: arctic-xs, arctic-s, arctic-m, arctic-m-long, arctic-l",
            model_str
        )),
    }
}

/// Format semantic search report for text output
fn format_semantic_text(report: &tldr_core::semantic::SemanticSearchReport) -> String {
    use colored::Colorize;

    let mut output = String::new();

    output.push_str(&format!(
        "{}: \"{}\"\n",
        "Semantic search".bold(),
        report.query.cyan()
    ));
    output.push_str(&format!(
        "Model: {} | Threshold: {:.2} | Searched: {} chunks\n\n",
        format!("{:?}", report.model).yellow(),
        0.5, // threshold from options
        report.total_chunks
    ));

    if report.results.is_empty() {
        output.push_str("No matches found above threshold.\n");
    } else {
        output.push_str(&format!(
            "{} ({} matches):\n\n",
            "Results".bold(),
            report.matches_above_threshold
        ));

        for (i, result) in report.results.iter().enumerate() {
            let func_name = result.function_name.as_deref().unwrap_or("<file>");
            let class_prefix = result
                .class_name
                .as_ref()
                .map(|c| format!("{}::", c))
                .unwrap_or_default();

            output.push_str(&format!(
                "{}. {}:{}{} (score: {:.2})\n",
                i + 1,
                result.file_path.display().to_string().green(),
                class_prefix,
                func_name.blue(),
                result.score
            ));
            output.push_str(&format!(
                "   Lines {}-{}\n",
                result.line_start, result.line_end
            ));

            if !result.snippet.is_empty() {
                output.push_str(&format!("   {}\n", result.snippet.dimmed()));
            }
            output.push('\n');
        }
    }

    output.push_str(&format!("Search completed in {}ms\n", report.latency_ms));

    output
}
