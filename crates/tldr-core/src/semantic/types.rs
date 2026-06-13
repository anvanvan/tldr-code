//! Core types for the semantic search module
//!
//! This module defines all data structures used by the semantic search system:
//! - `CodeChunk`: A piece of code that can be embedded
//! - `EmbeddedChunk`: A CodeChunk with its embedding vector
//! - `EmbeddingModel`: Available embedding models (Snowflake Arctic family)
//! - `ChunkGranularity`: File-level vs function-level chunking
//! - `SemanticSearchResult`: A single search result with score
//! - `SemanticSearchReport`: Full search report with results and metadata
//! - `EmbedReport`: Report from embedding generation
//! - `SimilarityReport`: Report from similarity search

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::Language;

/// Compute device for embedding inference.
///
/// The Rust port exposes `--device {cpu,gpu}` where `gpu` is the Apple-Silicon
/// CoreML/Metal path.
///
/// # Precedence
///
/// [`Device::resolve`] applies: explicit flag > `TLDR_DEVICE` env > default
/// ([`Device::Cpu`]). The default is **CPU**: ONNX-Runtime CoreML cannot
/// accelerate the Arctic-M embedder on Apple Silicon — every GPU/ANE compute
/// path measured ~4-5x SLOWER than CPU (onnxruntime #22007: graph-partition
/// churn), so CPU is both faster and leaner. (This reverses the earlier
/// GPU-default once the leak fix proved GPU has no speed benefit here.)
///
/// # Reachability
///
/// `Gpu` resolves to CoreML at runtime only when the crate is built with the
/// `coreml` cargo feature AND the platform supports CoreML (Apple Silicon).
/// Otherwise it transparently falls back to CPU (best-effort, never hard-fails).
/// The 33 GB CoreML leak is fixed (see `providers_for`), so `gpu` is safe — just
/// slower; opt in with `--device gpu` / `TLDR_DEVICE=gpu`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Device {
    /// CPU-only inference (ONNX CPU execution provider). **Default** — fastest
    /// and leanest for the Arctic-M embedder on this hardware.
    #[default]
    Cpu,
    /// GPU inference — CoreML on Apple Silicon when reachable, else CPU
    /// fallback. Safe and bounded (the 33 GB leak is fixed) but ~4-5x slower
    /// than CPU for this model; explicit opt-in only.
    Gpu,
}

impl Device {
    /// Resolve the effective device from an optional explicit flag value.
    ///
    /// Precedence: explicit `flag` > `TLDR_DEVICE` env var > [`Device::Gpu`]
    /// default. The accepted string spellings are `cpu` and `gpu`. For Python
    /// back-compat the alias `metal` maps to [`Device::Gpu`]. An unrecognized
    /// value (from flag or env) returns `Err` with a human-readable message.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tldr_core::semantic::Device;
    ///
    /// // Explicit flag wins.
    /// assert_eq!(Device::resolve(Some("cpu")).unwrap(), Device::Cpu);
    /// // metal is an accepted alias of gpu (Python parity).
    /// assert_eq!(Device::resolve(Some("metal")).unwrap(), Device::Gpu);
    /// ```
    pub fn resolve(flag: Option<&str>) -> Result<Self, String> {
        // 1. Explicit flag.
        if let Some(f) = flag {
            return Self::parse(f);
        }
        // 2. TLDR_DEVICE env.
        if let Ok(env) = std::env::var("TLDR_DEVICE") {
            let trimmed = env.trim();
            if !trimmed.is_empty() {
                return Self::parse(trimmed);
            }
        }
        // 3. Default.
        Ok(Device::default())
    }

    /// Parse a single device spelling (case-insensitive). `metal` is accepted
    /// as a Python-parity alias of `gpu`.
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "cpu" => Ok(Device::Cpu),
            "gpu" | "metal" => Ok(Device::Gpu),
            other => Err(format!(
                "Invalid device '{}'. Options: cpu, gpu",
                other
            )),
        }
    }

    /// Canonical lowercase string for this device (`"cpu"` / `"gpu"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Device::Cpu => "cpu",
            Device::Gpu => "gpu",
        }
    }
}

/// A chunk of code that can be embedded
///
/// Represents a discrete unit of code extracted from a source file,
/// either at file-level or function-level granularity.
///
/// # Example
///
/// ```rust
/// use std::path::PathBuf;
/// use tldr_core::semantic::CodeChunk;
/// use tldr_core::Language;
///
/// let chunk = CodeChunk {
///     file_path: PathBuf::from("src/main.rs"),
///     function_name: Some("process_data".to_string()),
///     class_name: None,
///     line_start: 10,
///     line_end: 25,
///     content: "fn process_data() { ... }".to_string(),
///     content_hash: "abc123".to_string(),
///     language: Language::Rust,
///     doc_kind: None,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CodeChunk {
    /// Source file path (relative to project root)
    pub file_path: PathBuf,

    /// Function/method name (None for file-level chunks)
    pub function_name: Option<String>,

    /// Class/struct name containing this function (if any)
    pub class_name: Option<String>,

    /// Start line number (1-indexed)
    pub line_start: u32,

    /// End line number (1-indexed, inclusive)
    pub line_end: u32,

    /// The source code text
    pub content: String,

    /// Content hash for cache invalidation (MD5)
    pub content_hash: String,

    /// Language of the code
    pub language: Language,

    /// Non-code document type, when this chunk was produced from a non-code
    /// file (`markdown`/`toml`/`yaml`/`json`/`shell`/`rst`/`text`/...).
    ///
    /// `None` for ordinary code chunks. When `Some(..)`, the chunk is a
    /// whole-file non-code unit (parity with Python's `unit_type="file"`
    /// non-code entries): the call-graph / enrichment passes MUST skip it and
    /// the `language` field is a placeholder only.
    ///
    /// `#[serde(default)]` keeps old cache/index JSON (which lack this field)
    /// deserializable as `None` — additive, no cache migration. The
    /// [`super::cache::EmbeddingCache`] key is `content_hash + path + fn +
    /// model`, disjoint from `doc_kind`, so this field never affects cache
    /// identity.
    #[serde(default)]
    pub doc_kind: Option<String>,
}

/// A CodeChunk with its embedding vector
///
/// Wraps a `CodeChunk` together with its dense embedding vector
/// for use in similarity search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedChunk {
    /// The original code chunk
    pub chunk: CodeChunk,

    /// Dense embedding vector (dimensions depend on model)
    pub embedding: Vec<f32>,
}

/// Supported embedding models (Snowflake Arctic family)
///
/// All models are from the Snowflake Arctic embedding family,
/// which is optimized for code and technical content.
///
/// # Model Comparison
///
/// | Model | Dimensions | Size | Context |
/// |-------|------------|------|---------|
/// | ArcticXS | 384 | 30MB | 512 |
/// | ArcticS | 384 | 90MB | 512 |
/// | ArcticM | 768 | 110MB | 512 |
/// | ArcticMLong | 768 | 110MB | 8192 |
/// | ArcticL | 1024 | 335MB | 512 |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EmbeddingModel {
    /// 384 dimensions, 30MB, 512 context - fastest, smallest
    ArcticXS,
    /// 384 dimensions, 90MB, 512 context - small
    ArcticS,
    /// 768 dimensions, 110MB, 512 context - balanced (DEFAULT)
    #[default]
    ArcticM,
    /// 768 dimensions, 110MB, 8192 context - long context
    ArcticMLong,
    /// 1024 dimensions, 335MB, 512 context - highest quality
    ArcticL,
}

impl EmbeddingModel {
    /// Get embedding dimension for this model
    ///
    /// Returns the size of the embedding vector produced by this model.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tldr_core::semantic::EmbeddingModel;
    ///
    /// assert_eq!(EmbeddingModel::ArcticM.dimensions(), 768);
    /// assert_eq!(EmbeddingModel::ArcticXS.dimensions(), 384);
    /// ```
    pub fn dimensions(&self) -> usize {
        match self {
            Self::ArcticXS | Self::ArcticS => 384,
            Self::ArcticM | Self::ArcticMLong => 768,
            Self::ArcticL => 1024,
        }
    }

    /// Get max context length (tokens)
    ///
    /// Returns the maximum number of tokens the model can process.
    /// Text longer than this will be truncated.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tldr_core::semantic::EmbeddingModel;
    ///
    /// assert_eq!(EmbeddingModel::ArcticM.max_context(), 512);
    /// assert_eq!(EmbeddingModel::ArcticMLong.max_context(), 8192);
    /// ```
    pub fn max_context(&self) -> usize {
        match self {
            Self::ArcticMLong => 8192,
            _ => 512,
        }
    }

    /// Get the model name as used by fastembed
    ///
    /// Returns a string identifier for the model.
    pub fn model_name(&self) -> &'static str {
        match self {
            Self::ArcticXS => "Snowflake/snowflake-arctic-embed-xs",
            Self::ArcticS => "Snowflake/snowflake-arctic-embed-s",
            Self::ArcticM => "Snowflake/snowflake-arctic-embed-m",
            Self::ArcticMLong => "Snowflake/snowflake-arctic-embed-m-long",
            Self::ArcticL => "Snowflake/snowflake-arctic-embed-l",
        }
    }
}

/// Granularity for code chunking
///
/// Determines how code is split into chunks for embedding.
///
/// # Variants
///
/// - `File`: One chunk per file (entire file content)
/// - `Function`: One chunk per function/method (DEFAULT)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChunkGranularity {
    /// One chunk per file
    File,
    /// One chunk per function/method (DEFAULT)
    #[default]
    Function,
}

/// Semantic search result
///
/// Represents a single result from a semantic search query,
/// including the matched code location and similarity score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticSearchResult {
    /// File path
    pub file_path: PathBuf,

    /// Function name (if function-level)
    pub function_name: Option<String>,

    /// Class name (if method)
    pub class_name: Option<String>,

    /// Cosine similarity score (0.0 to 1.0 for normalized vectors)
    pub score: f64,

    /// Start line
    pub line_start: u32,

    /// End line
    pub line_end: u32,

    /// Code snippet (truncated for display)
    pub snippet: String,

    /// Callees of this symbol (populated only when `--expand` is requested).
    ///
    /// Mirrors Python `semantic search --expand` which adds `calls` /
    /// `called_by` / `related` arrays per result. Absent (skipped in JSON)
    /// when expansion was not requested, so non-expand output is byte-identical
    /// to the pre-expand schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls: Option<Vec<String>>,

    /// Callers of this symbol (populated only when `--expand` is requested).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub called_by: Option<Vec<String>>,

    /// Related symbols of this symbol (populated only when `--expand` is
    /// requested).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related: Option<Vec<String>>,
}

/// Report from semantic search
///
/// Contains all results from a semantic search query along with
/// metadata about the search (model used, timing, etc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticSearchReport {
    /// Search results sorted by score (descending)
    pub results: Vec<SemanticSearchResult>,

    /// Total number of results returned (equals `results.len()`).
    ///
    /// schema-cleanup-v1 BUG-15: explicit count populated by the
    /// search executor so consumers don't need to re-derive it from
    /// `results | length`. Mirrors the new `total_results` field on
    /// `EnrichedSearchReport` so semantic search and BM25 search share
    /// the same schema shape.
    #[serde(default)]
    pub total_results: usize,

    /// Original query
    pub query: String,

    /// Model used for query embedding
    pub model: EmbeddingModel,

    /// Total chunks searched
    pub total_chunks: usize,

    /// Results above threshold
    pub matches_above_threshold: usize,

    /// Search latency in milliseconds
    pub latency_ms: u64,

    /// Whether cache was used
    pub cache_hit: bool,
}

/// Report from embedding generation
///
/// Contains metadata about an embedding operation,
/// including timing and cache statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedReport {
    /// Path that was embedded
    pub path: PathBuf,

    /// Model used
    pub model: EmbeddingModel,

    /// Granularity used
    pub granularity: ChunkGranularity,

    /// Number of chunks embedded
    pub chunks_embedded: usize,

    /// Number of chunks loaded from cache
    pub chunks_cached: usize,

    /// Embedded chunks (if output requested)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunks: Option<Vec<EmbeddedChunk>>,

    /// Total embedding time in milliseconds
    pub latency_ms: u64,
}

/// Report from similarity search
///
/// Contains results from finding code similar to a given chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityReport {
    /// Source file/function being compared
    pub source: CodeChunk,

    /// Similar code fragments
    pub similar: Vec<SemanticSearchResult>,

    /// Model used
    pub model: EmbeddingModel,

    /// Total chunks compared
    pub total_compared: usize,

    /// Whether self was excluded
    pub exclude_self: bool,
}

/// Options for embedding generation
#[derive(Debug, Clone)]
pub struct EmbedOptions {
    /// Model to use (default: ArcticM)
    pub model: EmbeddingModel,

    /// Show progress during embedding
    pub show_progress: bool,

    /// Batch size for embedding (default: 32)
    pub batch_size: usize,

    /// Compute device (default: [`Device::Gpu`], deliberate deviation from
    /// Python's CPU default).
    pub device: Device,
}

impl Default for EmbedOptions {
    fn default() -> Self {
        Self {
            model: EmbeddingModel::default(),
            show_progress: false,
            batch_size: 32,
            device: Device::default(),
        }
    }
}

/// Code chunking options
#[derive(Debug, Clone, Default)]
pub struct ChunkOptions {
    /// Granularity (file or function)
    pub granularity: ChunkGranularity,

    /// Maximum chunk size in characters (0 = no limit)
    pub max_chunk_size: usize,

    /// Include docstrings/comments in chunks
    pub include_docs: bool,

    /// Languages to process (None = auto-detect)
    pub languages: Option<Vec<Language>>,
}

/// Options for similarity search
#[derive(Debug, Clone)]
pub struct SearchOptions {
    /// Number of results to return
    pub top_k: usize,

    /// Minimum similarity threshold (0.0 to 1.0)
    pub threshold: f64,

    /// Model to use for query embedding
    pub model: EmbeddingModel,

    /// Exclude exact matches (for similarity search)
    pub exclude_self: bool,

    /// Add call-graph expansion (`calls`/`called_by`/`related`) to each result
    /// (parity with Python `semantic search --expand`).
    pub expand: bool,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            top_k: 10,
            threshold: 0.5,
            model: EmbeddingModel::default(),
            exclude_self: false,
            expand: false,
        }
    }
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Cache directory (default: ~/.cache/tldr/embeddings/)
    pub cache_dir: PathBuf,

    /// Maximum cache size in MB (default: 500)
    pub max_size_mb: usize,

    /// Cache entry TTL in days (default: 30)
    pub ttl_days: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            cache_dir: dirs::cache_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join("tldr")
                .join("embeddings"),
            max_size_mb: 500,
            ttl_days: 30,
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Number of entries
    pub entries: usize,
    /// Total size in bytes
    pub size_bytes: usize,
    /// Hit rate (0.0 to 1.0)
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;

    #[test]
    fn code_chunk_creation() {
        // GIVEN: Parameters for a code chunk
        let file_path = PathBuf::from("src/main.rs");
        let function_name = Some("process_data".to_string());
        let content = "fn process_data() { }".to_string();

        // WHEN: We create a CodeChunk
        let chunk = CodeChunk {
            file_path: file_path.clone(),
            function_name: function_name.clone(),
            class_name: None,
            line_start: 10,
            line_end: 20,
            content: content.clone(),
            content_hash: "abc123".to_string(),
            language: Language::Rust,
            doc_kind: None,
        };

        // THEN: Fields should be set correctly
        assert_eq!(chunk.file_path, file_path);
        assert_eq!(chunk.function_name, function_name);
        assert_eq!(chunk.line_start, 10);
        assert_eq!(chunk.line_end, 20);
        assert_eq!(chunk.content, content);
    }

    #[test]
    fn code_chunk_serialization_roundtrip() {
        // GIVEN: A CodeChunk
        let chunk = CodeChunk {
            file_path: PathBuf::from("test.py"),
            function_name: Some("foo".to_string()),
            class_name: Some("MyClass".to_string()),
            line_start: 1,
            line_end: 10,
            content: "def foo(): pass".to_string(),
            content_hash: "hash123".to_string(),
            language: Language::Python,
            doc_kind: None,
        };

        // WHEN: We serialize and deserialize
        let json = serde_json::to_string(&chunk).unwrap();
        let deserialized: CodeChunk = serde_json::from_str(&json).unwrap();

        // THEN: Roundtrip should preserve all fields
        assert_eq!(chunk.file_path, deserialized.file_path);
        assert_eq!(chunk.function_name, deserialized.function_name);
        assert_eq!(chunk.class_name, deserialized.class_name);
        assert_eq!(chunk.line_start, deserialized.line_start);
        assert_eq!(chunk.line_end, deserialized.line_end);
        assert_eq!(chunk.content, deserialized.content);
        assert_eq!(chunk.content_hash, deserialized.content_hash);
    }

    #[test]
    fn embedding_model_default_is_arctic_m() {
        let model = EmbeddingModel::default();
        assert_eq!(model, EmbeddingModel::ArcticM);
    }

    #[test]
    fn embedding_model_dimensions() {
        assert_eq!(EmbeddingModel::ArcticXS.dimensions(), 384);
        assert_eq!(EmbeddingModel::ArcticS.dimensions(), 384);
        assert_eq!(EmbeddingModel::ArcticM.dimensions(), 768);
        assert_eq!(EmbeddingModel::ArcticMLong.dimensions(), 768);
        assert_eq!(EmbeddingModel::ArcticL.dimensions(), 1024);
    }

    #[test]
    fn embedding_model_max_context() {
        assert_eq!(EmbeddingModel::ArcticXS.max_context(), 512);
        assert_eq!(EmbeddingModel::ArcticS.max_context(), 512);
        assert_eq!(EmbeddingModel::ArcticM.max_context(), 512);
        assert_eq!(EmbeddingModel::ArcticMLong.max_context(), 8192);
        assert_eq!(EmbeddingModel::ArcticL.max_context(), 512);
    }

    #[test]
    fn embedding_model_serialization() {
        // GIVEN: An embedding model
        let model = EmbeddingModel::ArcticM;

        // WHEN: We serialize it
        let json = serde_json::to_string(&model).unwrap();

        // THEN: It should use kebab-case
        assert_eq!(json, "\"arctic-m\"");
    }

    #[test]
    fn chunk_granularity_default_is_function() {
        let granularity = ChunkGranularity::default();
        assert_eq!(granularity, ChunkGranularity::Function);
    }

    #[test]
    fn semantic_search_result_ordering_by_score() {
        // GIVEN: Multiple search results with different scores
        let mut results = [
            SemanticSearchResult {
                file_path: PathBuf::from("a.rs"),
                function_name: Some("a".to_string()),
                class_name: None,
                score: 0.5,
                line_start: 1,
                line_end: 10,
                snippet: "fn a()".to_string(),
                calls: None,
                called_by: None,
                related: None,
            },
            SemanticSearchResult {
                file_path: PathBuf::from("b.rs"),
                function_name: Some("b".to_string()),
                class_name: None,
                score: 0.9,
                line_start: 1,
                line_end: 10,
                snippet: "fn b()".to_string(),
                calls: None,
                called_by: None,
                related: None,
            },
            SemanticSearchResult {
                file_path: PathBuf::from("c.rs"),
                function_name: Some("c".to_string()),
                class_name: None,
                score: 0.7,
                line_start: 1,
                line_end: 10,
                snippet: "fn c()".to_string(),
                calls: None,
                called_by: None,
                related: None,
            },
        ];

        // WHEN: We sort by score descending
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        // THEN: Results should be ordered by score (highest first)
        assert_eq!(results[0].function_name, Some("b".to_string())); // 0.9
        assert_eq!(results[1].function_name, Some("c".to_string())); // 0.7
        assert_eq!(results[2].function_name, Some("a".to_string())); // 0.5
    }

    #[test]
    fn search_options_default_values() {
        let options = SearchOptions::default();
        assert_eq!(options.top_k, 10);
        assert_eq!(options.threshold, 0.5);
        assert_eq!(options.model, EmbeddingModel::ArcticM);
        assert!(!options.exclude_self);
        assert!(!options.expand);
    }

    #[test]
    fn embed_options_default_values() {
        let options = EmbedOptions::default();
        assert_eq!(options.model, EmbeddingModel::ArcticM);
        assert!(!options.show_progress);
        assert!(options.batch_size >= 16 && options.batch_size <= 64);
    }
}
