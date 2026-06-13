//! Embedding service using fastembed-rs
//!
//! This module provides the `Embedder` struct for generating dense embeddings
//! from text using the Snowflake Arctic model family. It wraps fastembed-rs
//! to provide a type-safe, validated embedding service.
//!
//! # Architecture
//!
//! The Embedder handles:
//! - Model loading with progress reporting
//! - Model integrity validation (P0 mitigation)
//! - Single text and batch embedding
//! - Automatic normalization of output vectors
//!
//! # Example
//!
//! ```rust,ignore
//! use tldr_core::semantic::{Embedder, EmbeddingModel};
//!
//! // Create embedder with default model (Arctic-M)
//! let embedder = Embedder::new(EmbeddingModel::default())?;
//!
//! // Embed a single text
//! let embedding = embedder.embed_text("fn process_data() { }")?;
//! assert_eq!(embedding.len(), 768); // Arctic-M dimensions
//!
//! // Batch embedding
//! let texts = vec!["fn foo() {}", "fn bar() {}"];
//! let embeddings = embedder.embed_batch(texts, false)?;
//! assert_eq!(embeddings.len(), 2);
//! ```
//!
//! # P0 Mitigations (from premortem)
//!
//! - **1.1**: Validates ONNX runtime before model load
//! - **1.3**: Shows progress message before model download
//! - **4.1**: Model integrity validation after load (dimension check)

use fastembed::{
    EmbeddingModel as FastEmbeddingModel, ExecutionProviderDispatch, InitOptions, TextEmbedding,
};

use crate::error::TldrError;
use crate::semantic::similarity::normalize;
use crate::semantic::types::{Device, EmbeddingModel};
use crate::TldrResult;

/// Build the ONNX execution-provider list for a requested [`Device`].
///
/// The `coreml_available` parameter models whether a CoreML execution provider
/// is reachable in this build/platform (true only when the `coreml` cargo
/// feature is enabled). This is a pure, testable function so the device→EP
/// mapping can be unit-tested without loading a model.
///
/// Mapping:
/// - `(Gpu, true)`  -> `[CoreML, CPU]` — GPU best-effort with CPU fallback.
/// - `(Gpu, false)` -> `[CPU]`         — GPU requested but unreachable; CPU.
/// - `(Cpu, _)`     -> `[CPU]`         — explicit CPU.
///
/// fastembed/ort register providers in order and skip any that aren't
/// supported by the platform, so a leading CoreML EP transparently falls back
/// to CPU when CoreML can't be used at runtime (never hard-fails).
pub fn providers_for(device: Device, coreml_available: bool) -> Vec<ExecutionProviderDispatch> {
    let mut providers: Vec<ExecutionProviderDispatch> = Vec::new();

    #[cfg(feature = "coreml")]
    {
        if device == Device::Gpu && coreml_available {
            use ort::ep::coreml::{ComputeUnits, ModelFormat};
            // BARE `CoreML::default()` (NeuralNetwork + ComputeUnits::ALL + no cache)
            // leaks RSS without bound across `Run()` for BERT-class embedders on
            // Apple Silicon (onnxruntime #22007 lists `snowflake-arctic-embed-m`):
            // graph-partition churn + per-session recompilation. MLProgram (fewer
            // partitions) + a compiled-model cache bound it. Compute units and
            // static-shape capture are env-tunable for perf sweeps:
            //   TLDR_COREML_UNITS  = all | cpu_ane | cpu_gpu (default) | cpu_only
            //   TLDR_COREML_STATIC = set => RequireStaticInputShapes (fewer partitions)
            let units = match std::env::var("TLDR_COREML_UNITS").as_deref() {
                Ok("all") => ComputeUnits::All,
                Ok("cpu_ane") | Ok("ane") => ComputeUnits::CPUAndNeuralEngine,
                Ok("cpu_only") => ComputeUnits::CPUOnly,
                _ => ComputeUnits::CPUAndGPU,
            };
            let mut ep = ort::ep::CoreML::default()
                .with_model_format(ModelFormat::MLProgram)
                .with_compute_units(units)
                .with_model_cache_dir(coreml_cache_dir());
            if std::env::var_os("TLDR_COREML_STATIC").is_some() {
                ep = ep.with_static_input_shapes(true);
            }
            providers.push(ep.build());
        }
    }
    #[cfg(not(feature = "coreml"))]
    {
        // `coreml_available` is only meaningful under the `coreml` feature;
        // without it there is no CoreML EP to add. Silence the unused warning.
        let _ = (device, coreml_available);
    }

    // CPU is always the final (fallback) provider.
    #[cfg(feature = "coreml")]
    {
        providers.push(ort::ep::CPU::default().build());
    }

    providers
}

/// Directory for the CoreML EP's compiled-model cache (`ModelCacheDirectory`).
///
/// Reuses the same cache root as the fastembed model cache so the compiled
/// MLProgram is reused across runs instead of recompiled per session — a key
/// driver of the CoreML RSS growth mitigated in [`providers_for`]. Best-effort
/// create; ort surfaces a precise error if the path is unusable.
#[cfg(feature = "coreml")]
fn coreml_cache_dir() -> String {
    let dir = std::env::var("TLDR_FASTEMBED_CACHE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::cache_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join("tldr")
        })
        .join("coreml-cache");
    let _ = std::fs::create_dir_all(&dir);
    dir.to_string_lossy().into_owned()
}

/// Whether a CoreML execution provider is reachable in this build.
///
/// `true` only when compiled with the `coreml` cargo feature (which pulls the
/// `coreml`-gated `ort` dependency). On non-Apple platforms the CoreML EP will
/// still be skipped at runtime by ort's platform check, so this is a
/// build-time capability flag, not a runtime guarantee.
pub const fn coreml_available() -> bool {
    cfg!(feature = "coreml")
}

/// Options for embedding operations
///
/// Controls embedding behavior such as progress display and query prefixes.
#[derive(Debug, Clone, Default)]
pub struct EmbedOptions {
    /// Model to use (default: ArcticM)
    pub model: EmbeddingModel,

    /// Show progress during embedding
    pub show_progress: bool,

    /// Use query:/passage: prefixes for Arctic models (P1 mitigation 5.4)
    ///
    /// Arctic models perform better when queries use "query: " prefix
    /// and documents use "passage: " prefix. Enable this for search queries.
    pub use_prefix: bool,
}

/// Embedding service wrapping fastembed-rs
///
/// Provides validated embedding generation with automatic normalization.
/// The embedder performs model integrity checks on initialization to
/// detect corrupted model files early.
///
/// # Thread Safety
///
/// `Embedder` is `Send` but not `Sync` - create one per thread for
/// concurrent embedding.
pub struct Embedder {
    /// The underlying fastembed TextEmbedding instance
    model: TextEmbedding,

    /// Configuration for this embedder
    config: EmbeddingModel,
}

impl Embedder {
    /// Create a new embedder with the specified model
    ///
    /// # Arguments
    ///
    /// * `model` - The embedding model variant to use
    ///
    /// # Returns
    ///
    /// * `TldrResult<Self>` - Initialized embedder or error
    ///
    /// # Errors
    ///
    /// * `TldrError::ModelLoadError` - ONNX runtime unavailable or model download failed
    /// * `TldrError::Embedding` - Model integrity check failed
    ///
    /// # P0 Mitigations
    ///
    /// - Shows progress message before download (1.3)
    /// - Validates ONNX runtime (1.1)
    /// - Checks model integrity after load (4.1)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let embedder = Embedder::new(EmbeddingModel::ArcticM)?;
    /// ```
    pub fn new(model: EmbeddingModel) -> TldrResult<Self> {
        // Default device is CPU (deliberate deviation from Python's CPU
        // default); resolves to CoreML when built with `coreml` on Apple
        // Silicon, transparent CPU fallback otherwise.
        Self::with_device(model, Device::default())
    }

    /// Create a new embedder with an explicit compute [`Device`].
    ///
    /// Like [`Embedder::new`] but lets the caller request `gpu` (CoreML
    /// best-effort) or `cpu`. GPU is best-effort: when CoreML is unreachable
    /// (no `coreml` feature, or non-Apple platform) it transparently falls
    /// back to CPU and prints one diagnostic line (unless `TLDR_QUIET`).
    ///
    /// Also sets `with_show_download_progress(false)` to suppress fastembed's
    /// HF cold-load progress noise (parity with Python `_suppress_hf_noise`).
    pub fn with_device(model: EmbeddingModel, device: Device) -> TldrResult<Self> {
        // Convert our model enum to fastembed's
        let fast_model = Self::to_fastembed_model(model);

        // Best-effort GPU diagnostic: when GPU was requested but CoreML is not
        // reachable in this build, emit one line (unless quiet) so the user
        // knows the embedder fell back to CPU. Never hard-fail.
        if device == Device::Gpu
            && !coreml_available()
            && std::env::var_os("TLDR_QUIET").is_none()
        {
            eprintln!(
                "Note: GPU (CoreML) requested but not available in this build; using CPU."
            );
        }

        let providers = providers_for(device, coreml_available());

        // P0 Mitigation 1.3: Progress message before download.
        //
        // low-cleanup-bundle-v1 (L8): respect `TLDR_QUIET=1` so the CLI
        // commands `semantic`/`embed`/`similar`, when invoked with the
        // global `--quiet`/`-q` flag, silence the model-load banner. This
        // is the missing piece — `BuildOptions::show_progress` already
        // suppresses chunk/index progress, but the embedder's own banner
        // sat outside that path and printed unconditionally.
        if std::env::var_os("TLDR_QUIET").is_none() {
            eprintln!(
                "Loading embedding model ({})... First run may download ~{}MB model.",
                model.model_name(),
                Self::model_size_mb(model)
            );
        }

        // Initialize the model
        // P0 Mitigation 1.1: fastembed will fail here if ONNX runtime is unavailable
        //
        // M4 VAL-004 (v0.3.0): three-tier cache directory resolution. Without
        // an explicit cache_dir, fastembed defaults to a CWD-relative
        // `.fastembed_cache/` which (a) duplicates ~416 MB per working
        // directory and (b) races between parallel test processes on first
        // touch (`No such file or directory (os error 2)`). Tiers:
        //   1. `TLDR_FASTEMBED_CACHE` env var (test override / power user)
        //   2. `dirs::cache_dir().join("tldr/fastembed")` (per-platform XDG)
        //   3. `std::env::temp_dir().join("tldr/fastembed")` (last resort)
        let cache_dir: std::path::PathBuf = std::env::var("TLDR_FASTEMBED_CACHE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::cache_dir()
                    .unwrap_or_else(std::env::temp_dir)
                    .join("tldr")
                    .join("fastembed")
            });
        // Best-effort create; fastembed will surface a precise error if the
        // directory cannot be created or is not writable.
        let _ = std::fs::create_dir_all(&cache_dir);

        // Build init options:
        // - `with_show_download_progress(false)` suppresses fastembed's HF
        //   cold-load progress noise (parity with Python `_suppress_hf_noise`,
        //   9fa72c2); the embedder's own load banner is gated separately by
        //   `TLDR_QUIET` above.
        // - `with_execution_providers(providers)` wires the CoreML+CPU (or
        //   CPU-only) EP list. ort registers them in order, skipping any not
        //   supported on the current platform -> transparent CPU fallback.
        let mut init_options = InitOptions::new(fast_model)
            .with_cache_dir(cache_dir)
            .with_show_download_progress(false);
        if !providers.is_empty() {
            init_options = init_options.with_execution_providers(providers);
        }

        let mut embedding = TextEmbedding::try_new(init_options).map_err(|e| {
            TldrError::ModelLoadError {
                model: model.model_name().to_string(),
                detail: e.to_string(),
            }
        })?;

        // P0 Mitigation 4.1: Model integrity check
        // Embed a known input and verify dimensions
        let test_result = embedding
            .embed(vec!["test"], None)
            .map_err(|e| TldrError::Embedding(format!("Model integrity check failed: {}", e)))?;

        if test_result.is_empty() {
            return Err(TldrError::Embedding(
                "Model integrity check failed: empty result".to_string(),
            ));
        }

        let actual_dims = test_result[0].len();
        let expected_dims = model.dimensions();

        if actual_dims != expected_dims {
            return Err(TldrError::Embedding(format!(
                "Model integrity check failed: expected {} dimensions, got {}",
                expected_dims, actual_dims
            )));
        }

        Ok(Self {
            model: embedding,
            config: model,
        })
    }

    /// Convert our EmbeddingModel to fastembed's enum
    fn to_fastembed_model(model: EmbeddingModel) -> FastEmbeddingModel {
        match model {
            EmbeddingModel::ArcticXS => FastEmbeddingModel::SnowflakeArcticEmbedXS,
            EmbeddingModel::ArcticS => FastEmbeddingModel::SnowflakeArcticEmbedS,
            EmbeddingModel::ArcticM => FastEmbeddingModel::SnowflakeArcticEmbedM,
            EmbeddingModel::ArcticMLong => FastEmbeddingModel::SnowflakeArcticEmbedMLong,
            EmbeddingModel::ArcticL => FastEmbeddingModel::SnowflakeArcticEmbedL,
        }
    }

    /// Get approximate model size in MB for progress messages
    fn model_size_mb(model: EmbeddingModel) -> usize {
        match model {
            EmbeddingModel::ArcticXS => 30,
            EmbeddingModel::ArcticS => 90,
            EmbeddingModel::ArcticM | EmbeddingModel::ArcticMLong => 110,
            EmbeddingModel::ArcticL => 335,
        }
    }

    /// Embed a single text string
    ///
    /// Returns a normalized embedding vector with L2 norm = 1.0.
    ///
    /// # Arguments
    ///
    /// * `text` - Text to embed
    ///
    /// # Returns
    ///
    /// * `TldrResult<Vec<f32>>` - Normalized embedding vector
    ///
    /// # Invariants
    ///
    /// * Output length == model.dimensions()
    /// * Output is normalized (L2 norm == 1.0)
    /// * Empty input returns zero vector
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let embedding = embedder.embed_text("fn process_data() { }")?;
    /// assert_eq!(embedding.len(), embedder.config().dimensions());
    /// ```
    pub fn embed_text(&mut self, text: &str) -> TldrResult<Vec<f32>> {
        // Handle empty input - return zero vector
        if text.is_empty() {
            return Ok(vec![0.0; self.config.dimensions()]);
        }

        let result = self
            .model
            .embed(vec![text], None)
            .map_err(|e| TldrError::Embedding(format!("Failed to embed text: {}", e)))?;

        let mut embedding = result
            .into_iter()
            .next()
            .ok_or_else(|| TldrError::Embedding("No embedding returned".to_string()))?;

        // Normalize to unit length
        normalize(&mut embedding);

        Ok(embedding)
    }

    /// Embed multiple texts in a batch
    ///
    /// More efficient than calling `embed_text` multiple times as it batches
    /// the model inference.
    ///
    /// # Arguments
    ///
    /// * `texts` - Texts to embed
    /// * `show_progress` - Whether to show progress (uses batch_size for chunking)
    ///
    /// # Returns
    ///
    /// * `TldrResult<Vec<Vec<f32>>>` - Normalized embedding vectors
    ///
    /// # Performance
    ///
    /// * Batching reduces overhead for multiple texts
    /// * Default batch size: 32
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let texts = vec!["fn foo() {}", "fn bar() {}"];
    /// let embeddings = embedder.embed_batch(texts, false)?;
    /// assert_eq!(embeddings.len(), 2);
    /// ```
    pub fn embed_batch(
        &mut self,
        texts: Vec<&str>,
        show_progress: bool,
    ) -> TldrResult<Vec<Vec<f32>>> {
        // Handle empty input
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        // Use batch size for progress (affects how fastembed chunks the work)
        let batch_size = if show_progress { Some(32) } else { None };

        let results = self
            .model
            .embed(texts, batch_size)
            .map_err(|e| TldrError::Embedding(format!("Failed to embed batch: {}", e)))?;

        // Normalize all embeddings
        let normalized: Vec<Vec<f32>> = results
            .into_iter()
            .map(|mut v| {
                normalize(&mut v);
                v
            })
            .collect();

        Ok(normalized)
    }

    /// Get the model configuration
    ///
    /// Returns the `EmbeddingModel` variant this embedder was created with.
    pub fn config(&self) -> EmbeddingModel {
        self.config
    }

    /// Get embedding dimensions for this model
    ///
    /// Convenience method that delegates to `config().dimensions()`.
    pub fn dimensions(&self) -> usize {
        self.config.dimensions()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::similarity::is_normalized;

    // =========================================================================
    // All embedding tests are #[ignore] by default since they require
    // model download (~110MB for Arctic-M). Run with:
    //   cargo test --release -p tldr-core -- --ignored embedder
    // =========================================================================

    #[test]
    fn embed_options_default_values() {
        // GIVEN/WHEN: Default EmbedOptions
        let options = EmbedOptions::default();

        // THEN: Should have sensible defaults
        assert_eq!(options.model, EmbeddingModel::ArcticM);
        assert!(!options.show_progress);
        assert!(!options.use_prefix);
    }

    #[test]
    #[ignore = "Requires model download (~110MB)"]
    fn embedder_new_initializes_model() {
        // GIVEN: A model variant
        let model = EmbeddingModel::ArcticM;

        // WHEN: We create an embedder
        let embedder = Embedder::new(model);

        // THEN: Should succeed
        assert!(
            embedder.is_ok(),
            "Failed to initialize: {:?}",
            embedder.err()
        );

        let embedder = embedder.unwrap();
        assert_eq!(embedder.config(), model);
        assert_eq!(embedder.dimensions(), 768);
    }

    #[test]
    #[ignore = "Requires model download (~110MB)"]
    fn embedder_embed_text_returns_correct_dimensions() {
        // GIVEN: An initialized embedder
        let mut embedder = Embedder::new(EmbeddingModel::ArcticM).expect("Failed to init");

        // WHEN: We embed text
        let embedding = embedder
            .embed_text("fn process_data() { }")
            .expect("Failed to embed");

        // THEN: Should have correct dimensions
        assert_eq!(embedding.len(), 768, "Expected 768 dimensions for ArcticM");
    }

    #[test]
    #[ignore = "Requires model download (~110MB)"]
    fn embedder_embed_text_is_normalized() {
        // GIVEN: An initialized embedder
        let mut embedder = Embedder::new(EmbeddingModel::ArcticM).expect("Failed to init");

        // WHEN: We embed text
        let embedding = embedder
            .embed_text("fn process_data() { }")
            .expect("Failed to embed");

        // THEN: Embedding should be normalized (L2 norm = 1.0)
        assert!(
            is_normalized(&embedding),
            "Embedding should have L2 norm = 1.0"
        );
    }

    #[test]
    #[ignore = "Requires model download (~110MB)"]
    fn embedder_batch_embedding_matches_single() {
        // GIVEN: An initialized embedder and some texts
        let mut embedder = Embedder::new(EmbeddingModel::ArcticM).expect("Failed to init");
        let text1 = "fn foo() { }";
        let text2 = "fn bar() { }";

        // WHEN: We embed individually and in batch
        let single1 = embedder.embed_text(text1).expect("Failed single embed 1");
        let single2 = embedder.embed_text(text2).expect("Failed single embed 2");
        let batch = embedder
            .embed_batch(vec![text1, text2], false)
            .expect("Failed batch embed");

        // THEN: Results should match (within floating point tolerance)
        assert_eq!(batch.len(), 2);

        // Compare with tolerance for floating point differences
        for (a, b) in single1.iter().zip(batch[0].iter()) {
            assert!(
                (a - b).abs() < 1e-5,
                "Single vs batch mismatch: {} vs {}",
                a,
                b
            );
        }
        for (a, b) in single2.iter().zip(batch[1].iter()) {
            assert!(
                (a - b).abs() < 1e-5,
                "Single vs batch mismatch: {} vs {}",
                a,
                b
            );
        }
    }

    #[test]
    #[ignore = "Requires model download (~110MB)"]
    fn embedder_empty_input_returns_zero_vector() {
        // GIVEN: An initialized embedder
        let mut embedder = Embedder::new(EmbeddingModel::ArcticM).expect("Failed to init");

        // WHEN: We embed empty string
        let embedding = embedder.embed_text("").expect("Failed to embed empty");

        // THEN: Should return zero vector with correct dimensions
        assert_eq!(embedding.len(), 768);
        assert!(
            embedding.iter().all(|&x| x == 0.0),
            "Empty input should produce zero vector"
        );
    }

    #[test]
    #[ignore = "Requires model download (~110MB)"]
    fn embedder_batch_empty_list_returns_empty() {
        // GIVEN: An initialized embedder
        let mut embedder = Embedder::new(EmbeddingModel::ArcticM).expect("Failed to init");

        // WHEN: We embed empty list
        let embeddings = embedder
            .embed_batch(vec![], false)
            .expect("Failed to embed empty batch");

        // THEN: Should return empty list
        assert!(embeddings.is_empty());
    }

    #[test]
    #[ignore = "Requires model download (~30MB for XS)"]
    fn embedder_xs_model_dimensions() {
        // GIVEN: Arctic XS model (smallest, fastest for testing)
        let mut embedder = Embedder::new(EmbeddingModel::ArcticXS).expect("Failed to init XS");

        // WHEN: We embed text
        let embedding = embedder.embed_text("test").expect("Failed to embed");

        // THEN: Should have 384 dimensions
        assert_eq!(embedding.len(), 384);
        assert!(is_normalized(&embedding));
    }

    #[test]
    #[ignore = "Requires model download (~110MB)"]
    fn embedder_deterministic_results() {
        // GIVEN: An initialized embedder
        let mut embedder = Embedder::new(EmbeddingModel::ArcticM).expect("Failed to init");
        let text = "fn process_data(input: &str) -> Result<Output>";

        // WHEN: We embed the same text twice
        let e1 = embedder.embed_text(text).expect("Failed embed 1");
        let e2 = embedder.embed_text(text).expect("Failed embed 2");

        // THEN: Results should be identical
        assert_eq!(e1.len(), e2.len());
        for (a, b) in e1.iter().zip(e2.iter()) {
            assert!(
                (a - b).abs() < 1e-6,
                "Embeddings should be deterministic: {} vs {}",
                a,
                b
            );
        }
    }
}
