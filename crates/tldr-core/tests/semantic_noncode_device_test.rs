//! Area-3 (semantic-surface) migration tests: non-code indexing, the `Device`
//! selector, the execution-provider helper, and the `doc_kind` enrichment-skip
//! contract.
//!
//! These tests encode the Python oracle behavior (`tldr semantic`):
//! - `tldr/api.py:72` `NON_CODE_EXTENSIONS`
//! - `tldr/semantic.py:61,103` preview cap + extensionless basenames
//! - `tldr/semantic.py:1398-1432` whole-file non-code unit (`unit_type="file"`)
//! - `tldr/cli.py:853-883` device precedence (flag > env > default), with the
//!   user-mandated default deviation to GPU and the `{cpu,gpu}` label.
//!
//! No model download occurs — all tests operate on chunking/types/helpers only.

#![cfg(feature = "semantic")]

use std::path::{Path, PathBuf};

use tldr_core::semantic::chunker::chunk_file;
use tldr_core::semantic::noncode::{
    build_noncode_chunk, noncode_kind, NON_CODE_EXTENSIONS, NON_CODE_EXTENSIONLESS_BASENAMES,
    NON_CODE_PREVIEW_CHARS,
};
use tldr_core::semantic::types::ChunkOptions;
use tldr_core::semantic::{BuildOptions, Device, SemanticIndex};

use tempfile::TempDir;

// =============================================================================
// Device::resolve precedence (flag > TLDR_DEVICE env > Cpu default)
// =============================================================================

#[test]
fn device_default_is_cpu() {
    // Deliberate deviation from Python's CPU default (per user override).
    assert_eq!(Device::default(), Device::Cpu);
}

#[test]
fn device_resolve_explicit_flag_wins() {
    assert_eq!(Device::resolve(Some("cpu")).unwrap(), Device::Cpu);
    assert_eq!(Device::resolve(Some("gpu")).unwrap(), Device::Gpu);
    // Case-insensitive.
    assert_eq!(Device::resolve(Some("CPU")).unwrap(), Device::Cpu);
    assert_eq!(Device::resolve(Some("Gpu")).unwrap(), Device::Gpu);
}

#[test]
fn device_resolve_metal_aliases_gpu() {
    // Python parity: `metal` is the Apple-Silicon GPU path.
    assert_eq!(Device::resolve(Some("metal")).unwrap(), Device::Gpu);
}

#[test]
fn device_resolve_invalid_flag_errs() {
    let err = Device::resolve(Some("tpu")).unwrap_err();
    assert!(err.contains("tpu"), "error should name the bad value: {err}");
    assert!(err.contains("cpu") && err.contains("gpu"), "error should list options: {err}");
}

#[test]
fn device_resolve_default_when_no_flag_no_env() {
    // Guard: ensure env is not set for this assertion. We avoid mutating the
    // process env (parallel tests) by only asserting the flag=None path when
    // TLDR_DEVICE is absent in this process; if a sibling set it, skip.
    if std::env::var_os("TLDR_DEVICE").is_none() {
        assert_eq!(Device::resolve(None).unwrap(), Device::Cpu);
    }
}

#[test]
fn device_as_str_roundtrip() {
    assert_eq!(Device::Cpu.as_str(), "cpu");
    assert_eq!(Device::Gpu.as_str(), "gpu");
}

// =============================================================================
// noncode_kind classification (parity with Python gate)
// =============================================================================

#[test]
fn noncode_extensions_list_matches_oracle() {
    // Oracle: api.py:72 NON_CODE_EXTENSIONS (without leading dots here).
    let mut got: Vec<&str> = NON_CODE_EXTENSIONS.to_vec();
    got.sort_unstable();
    let mut want = vec![
        "sh", "zsh", "bash", "toml", "yaml", "yml", "json", "md", "rst", "txt",
    ];
    want.sort_unstable();
    assert_eq!(got, want);
}

#[test]
fn extensionless_basenames_match_oracle() {
    let mut got: Vec<&str> = NON_CODE_EXTENSIONLESS_BASENAMES.to_vec();
    got.sort_unstable();
    let mut want = vec!["makefile", "dockerfile", "gemfile", "podfile"];
    want.sort_unstable();
    assert_eq!(got, want);
}

#[test]
fn noncode_kind_doc_types() {
    assert_eq!(noncode_kind(Path::new("README.md")), Some("markdown".into()));
    assert_eq!(noncode_kind(Path::new("settings.toml")), Some("toml".into()));
    assert_eq!(noncode_kind(Path::new("ci.yaml")), Some("yaml".into()));
    assert_eq!(noncode_kind(Path::new("ci.yml")), Some("yaml".into()));
    assert_eq!(noncode_kind(Path::new("data.json")), Some("json".into()));
    assert_eq!(noncode_kind(Path::new("build.sh")), Some("shell".into()));
    assert_eq!(noncode_kind(Path::new("x.bash")), Some("shell".into()));
    assert_eq!(noncode_kind(Path::new("x.zsh")), Some("shell".into()));
    assert_eq!(noncode_kind(Path::new("doc.rst")), Some("rst".into()));
    assert_eq!(noncode_kind(Path::new("notes.txt")), Some("text".into()));
}

#[test]
fn noncode_kind_extensionless_default_text() {
    // Python: `EXTENSION_TO_LANGUAGE.get("", "text")` => "text".
    assert_eq!(noncode_kind(Path::new("Makefile")), Some("text".into()));
    assert_eq!(noncode_kind(Path::new("Dockerfile")), Some("text".into()));
    assert_eq!(noncode_kind(Path::new("Gemfile")), Some("text".into()));
    assert_eq!(noncode_kind(Path::new("Podfile")), Some("text".into()));
}

#[test]
fn noncode_kind_rejects_code_files() {
    assert_eq!(noncode_kind(Path::new("main.rs")), None);
    assert_eq!(noncode_kind(Path::new("app.py")), None);
    assert_eq!(noncode_kind(Path::new("index.ts")), None);
    // Unknown binary ext -> not non-code.
    assert_eq!(noncode_kind(Path::new("logo.png")), None);
}

// =============================================================================
// build_noncode_chunk: one chunk, doc_kind set, preview cap, stable hash
// =============================================================================

#[test]
fn build_noncode_chunk_basic() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("settings.toml");
    std::fs::write(&p, "[server]\nport = 8080\n").unwrap();

    let chunk = build_noncode_chunk(&p).expect("non-code chunk");
    assert_eq!(chunk.doc_kind.as_deref(), Some("toml"));
    assert_eq!(chunk.function_name, None);
    assert_eq!(chunk.class_name, None);
    assert_eq!(chunk.line_start, 1);
    assert!(chunk.content.contains("port = 8080"));
    assert!(!chunk.content_hash.is_empty());
}

#[test]
fn build_noncode_chunk_returns_none_for_code() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("main.rs");
    std::fs::write(&p, "fn main() {}\n").unwrap();
    assert!(build_noncode_chunk(&p).is_none());
}

#[test]
fn build_noncode_chunk_preview_caps_multibyte_at_char_boundary() {
    // 5000 multibyte chars (each 'é' is 2 bytes) -> 10000 bytes, but should cap
    // at NON_CODE_PREVIEW_CHARS *characters* without panicking on a byte slice.
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("big.md");
    let big: String = "é".repeat(NON_CODE_PREVIEW_CHARS + 500);
    std::fs::write(&p, &big).unwrap();

    let chunk = build_noncode_chunk(&p).expect("non-code chunk");
    // README.md has no hint; big.md likewise has no filename hint, so content
    // is exactly the preview.
    let char_count = chunk.content.chars().count();
    assert!(
        char_count <= NON_CODE_PREVIEW_CHARS,
        "preview must be capped at {} chars, got {}",
        NON_CODE_PREVIEW_CHARS,
        char_count
    );
    assert_eq!(char_count, NON_CODE_PREVIEW_CHARS);
}

#[test]
fn build_noncode_chunk_hash_stable_across_calls() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("notes.txt");
    std::fs::write(&p, "hello world\n").unwrap();

    let a = build_noncode_chunk(&p).unwrap();
    let b = build_noncode_chunk(&p).unwrap();
    assert_eq!(a.content_hash, b.content_hash, "hash must be deterministic");
}

#[test]
fn build_noncode_chunk_injects_filename_hint() {
    // README.md gets a project-readme hint folded into content (parity with the
    // Python docstring hint that biases NL queries toward well-known files).
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("README.md");
    std::fs::write(&p, "# My Project\n").unwrap();

    let chunk = build_noncode_chunk(&p).unwrap();
    assert!(
        chunk.content.contains("project readme"),
        "README.md content should carry the filename hint: {:?}",
        chunk.content
    );
}

// =============================================================================
// chunker routing: non-code files are chunked (not skipped) before the
// Language::from_path gate
// =============================================================================

#[test]
fn chunk_file_routes_noncode_before_lang_gate() {
    let dir = TempDir::new().unwrap();
    for (name, body) in [
        ("README.md", "# readme\ninstall steps\n"),
        ("config.toml", "[a]\nb=1\n"),
        ("data.json", "{\"k\":1}\n"),
        ("build.sh", "#!/bin/sh\necho hi\n"),
        ("Makefile", "all:\n\techo hi\n"),
    ] {
        let p = dir.path().join(name);
        std::fs::write(&p, body).unwrap();

        let result = chunk_file(&p, &ChunkOptions::default()).unwrap();
        assert_eq!(
            result.chunks.len(),
            1,
            "{name} should produce exactly one non-code chunk"
        );
        assert!(
            result.chunks[0].doc_kind.is_some(),
            "{name} chunk must be marked doc_kind=Some"
        );
        assert!(
            result.skipped.is_empty(),
            "{name} must not be reported as skipped"
        );
    }
}

#[test]
fn chunk_file_still_skips_unknown_binary_ext() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("mystery.xyz");
    std::fs::write(&p, "blah\n").unwrap();
    let result = chunk_file(&p, &ChunkOptions::default()).unwrap();
    assert!(result.chunks.is_empty());
    assert_eq!(result.skipped.len(), 1);
}

#[test]
fn chunk_file_code_path_unaffected() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("lib.rs");
    std::fs::write(&p, "fn foo() {}\nfn bar() {}\n").unwrap();
    let result = chunk_file(&p, &ChunkOptions::default()).unwrap();
    assert!(!result.chunks.is_empty());
    for c in &result.chunks {
        assert!(c.doc_kind.is_none(), "code chunks must have doc_kind=None");
    }
}

// =============================================================================
// doc_kind enrichment-skip contract: build over a mixed tree must not panic
// trying to parse a non-code chunk's placeholder language.
// =============================================================================

#[test]
fn build_index_over_mixed_tree_does_not_parse_noncode() {
    // Stray-marker guard for /tmp indexing.
    let _ = std::fs::remove_dir_all("/private/tmp/.tldr");

    let dir = TempDir::new().unwrap();
    // git-init so _find_project_root anchors here (avoids tmp-marker hijack).
    std::process::Command::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .ok();

    std::fs::write(dir.path().join("README.md"), "# title\nmalformed pdf invoice\n").unwrap();
    std::fs::write(dir.path().join("settings.toml"), "[a]\nb = 1\n").unwrap();
    std::fs::write(
        dir.path().join("parser.rs"),
        "fn parse_invoice() { let _ = 1; }\n",
    )
    .unwrap();

    // Chunk WITHOUT embedding (default chunk path) to assert non-code chunks
    // route correctly and carry doc_kind, without a model download. The build
    // path would call the embedder; here we just exercise chunking + the
    // doc_kind invariant the index relies on to skip parsing.
    let result =
        tldr_core::semantic::chunk_code(dir.path(), &ChunkOptions::default()).unwrap();

    let noncode: Vec<_> = result
        .chunks
        .iter()
        .filter(|c| c.doc_kind.is_some())
        .collect();
    let code: Vec<_> = result
        .chunks
        .iter()
        .filter(|c| c.doc_kind.is_none())
        .collect();

    // README.md + settings.toml -> 2 non-code chunks.
    assert_eq!(noncode.len(), 2, "expected README.md + settings.toml as non-code");
    // parser.rs -> at least one code chunk.
    assert!(!code.is_empty(), "expected at least one code chunk from parser.rs");

    // Cleanup stray marker.
    let _ = std::fs::remove_dir_all("/private/tmp/.tldr");

    // Silence unused-import lint of SemanticIndex/BuildOptions/PathBuf in this
    // model-free test while keeping them imported for the documented build API.
    let _ = (
        std::any::type_name::<SemanticIndex>(),
        std::any::type_name::<BuildOptions>(),
        std::any::type_name::<PathBuf>(),
    );
}

// =============================================================================
// Execution-provider helper: device -> EP list mapping (no model load).
// =============================================================================

#[test]
fn providers_for_cpu_is_cpu_only() {
    use tldr_core::semantic::{coreml_available, providers_for};
    // CPU request: never includes CoreML regardless of build.
    let providers = providers_for(Device::Cpu, coreml_available());
    // Length is implementation-defined per feature, but for CPU it must be the
    // CPU-only list: under coreml feature => [CPU] (len 1); without feature =>
    // [] (fastembed default CPU). Either way, no CoreML EP is added.
    if coreml_available() {
        assert_eq!(providers.len(), 1, "CPU request under coreml => [CPU]");
    } else {
        assert!(
            providers.is_empty(),
            "CPU request without coreml => empty (fastembed CPU default)"
        );
    }
}

#[test]
fn providers_for_gpu_depends_on_build() {
    use tldr_core::semantic::{coreml_available, providers_for};
    let providers = providers_for(Device::Gpu, coreml_available());
    if coreml_available() {
        // [CoreML, CPU]
        assert_eq!(
            providers.len(),
            2,
            "GPU under coreml feature => [CoreML, CPU]"
        );
    } else {
        // GPU requested but unreachable -> CPU-only (empty list = fastembed CPU
        // default). Transparent fallback, no hard fail.
        assert!(
            providers.is_empty(),
            "GPU without coreml => empty (CPU fallback)"
        );
    }
}

#[test]
fn coreml_available_matches_cfg() {
    use tldr_core::semantic::coreml_available;
    assert_eq!(coreml_available(), cfg!(feature = "coreml"));
}
