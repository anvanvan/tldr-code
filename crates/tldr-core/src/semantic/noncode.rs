//! Non-code file indexing for semantic search.
//!
//! Ports the Python `tldr semantic` non-code path so build/config/doc files
//! (`.sh` scripts, `.toml`/`.yaml` config, `README.md`, `Makefile`, ...) are
//! indexed as whole-file embedding units and surface in semantic search.
//!
//! # Python oracle
//!
//! - `tldr/api.py:72` `NON_CODE_EXTENSIONS`
//! - `tldr/semantic.py:103` `_NON_CODE_EXTENSIONLESS_BASENAMES`
//! - `tldr/semantic.py:61` `_NON_CODE_PREVIEW_CHARS = 8000`
//! - `tldr/semantic.py:1398-1432` `_build_non_code_file_entry` — emits one
//!   whole-file unit (`unit_type="file"`), `language =
//!   EXTENSION_TO_LANGUAGE.get(suffix, "text")`, plus a filename-hint
//!   docstring.
//!
//! Each non-code file becomes exactly one [`CodeChunk`] with
//! [`CodeChunk::doc_kind`] set to the document type (`markdown`/`toml`/`shell`/
//! ...). Downstream call-graph / enrichment passes MUST skip chunks where
//! `doc_kind.is_some()`.

use std::path::Path;

use crate::semantic::types::CodeChunk;
use crate::Language;

/// Whole-file preview cap, in **characters** (not bytes), char-boundary-safe.
///
/// Parity with Python `_NON_CODE_PREVIEW_CHARS` (`semantic.py:61`).
pub const NON_CODE_PREVIEW_CHARS: usize = 8000;

/// Non-code file suffixes the semantic indexer includes.
///
/// Parity with Python `NON_CODE_EXTENSIONS` (`api.py:72`). Entries are stored
/// WITHOUT the leading dot and matched case-insensitively.
pub const NON_CODE_EXTENSIONS: &[&str] = &[
    "sh", "zsh", "bash", "toml", "yaml", "yml", "json", "md", "rst", "txt",
];

/// Extensionless basenames (lowercased) that reach the non-code path despite
/// having no suffix.
///
/// Parity with Python `_NON_CODE_EXTENSIONLESS_BASENAMES` (`semantic.py:103`).
pub const NON_CODE_EXTENSIONLESS_BASENAMES: &[&str] =
    &["makefile", "dockerfile", "gemfile", "podfile"];

/// Map a non-code extension (lowercased, no dot) to its document-type tag.
///
/// Parity with the non-code rows of Python `EXTENSION_TO_LANGUAGE`
/// (`lang_constants.py`). Returns `None` for extensions outside
/// [`NON_CODE_EXTENSIONS`].
fn ext_to_doc_kind(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "sh" | "bash" | "zsh" => "shell",
        "toml" => "toml",
        "yaml" | "yml" => "yaml",
        "json" => "json",
        "md" => "markdown",
        "rst" => "rst",
        "txt" => "text",
        _ => return None,
    })
}

/// Concise filename-derived hints injected into the embedding text for
/// well-known non-code files.
///
/// Parity with Python `_NON_CODE_FILENAME_HINTS` (`semantic.py:72`). Lookup is
/// by lowercased basename. Returns `""` when no hint is known.
fn filename_hint(basename_lower: &str) -> &'static str {
    match basename_lower {
        "readme.md" | "readme.rst" | "readme.txt" | "readme" => {
            "project readme: overview installation usage"
        }
        "contributing.md" => "contributor guide: install dev dependencies run tests",
        "changelog.md" => "changelog: release notes version history",
        "license" | "license.md" | "license.txt" => "license",
        "pyproject.toml" => "python project manifest: install dependencies metadata build",
        "setup.py" => "python setup script: install dependencies package metadata",
        "setup.cfg" => "python setup config: install dependencies package metadata",
        "requirements.txt" => "python pip requirements: install dependencies",
        "requirements-dev.txt" => {
            "python pip dev requirements: install development dependencies"
        }
        "package.json" => "node.js package manifest: install dependencies scripts metadata",
        "package-lock.json" => "node.js dependency lockfile",
        "cargo.toml" => "rust crate manifest: install dependencies build config",
        "cargo.lock" => "rust dependency lockfile",
        "go.mod" => "go module manifest: install dependencies module path",
        "gemfile" => "ruby bundler manifest: install dependencies",
        "podfile" => "cocoapods manifest: install ios macos dependencies",
        "build.sh" => "build shell script",
        "install.sh" => "install shell script: install dependencies set up project",
        "dockerfile" => "container image build instructions",
        "makefile" => "gnu make build configuration",
        _ => "",
    }
}

/// Classify a path as a non-code file, returning its document-type tag.
///
/// Returns `Some(doc_kind)` if the path's extension is in
/// [`NON_CODE_EXTENSIONS`] OR its (lowercased) basename is in
/// [`NON_CODE_EXTENSIONLESS_BASENAMES`]; otherwise `None`.
///
/// Mirrors the Python gate in `_build_non_code_file_entry`:
/// `suffix in NON_CODE_EXTENSIONS or name.lower() in EXTENSIONLESS_BASENAMES`,
/// with the document type from `EXTENSION_TO_LANGUAGE.get(suffix, "text")`
/// (extensionless basenames have an empty suffix and so default to `"text"`).
///
/// # Examples
///
/// ```rust
/// use std::path::Path;
/// use tldr_core::semantic::noncode::noncode_kind;
///
/// assert_eq!(noncode_kind(Path::new("README.md")), Some("markdown".to_string()));
/// assert_eq!(noncode_kind(Path::new("config.TOML")), Some("toml".to_string()));
/// assert_eq!(noncode_kind(Path::new("Makefile")), Some("text".to_string()));
/// assert_eq!(noncode_kind(Path::new("main.rs")), None);
/// ```
pub fn noncode_kind(path: &Path) -> Option<String> {
    // Extension match (case-insensitive, no dot).
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();
        if let Some(kind) = ext_to_doc_kind(&ext_lower) {
            return Some(kind.to_string());
        }
        // An extension that is not a known non-code suffix => not non-code.
        // (Falls through to the extensionless-basename check only when there
        // is no extension; a `foo.rs` must NOT be treated as non-code.)
        // NOTE: Python checks `suffix in NON_CODE_EXTENSIONS` first; if the
        // file has a suffix that is not in the set, the basename check below
        // still runs in Python (basenames like "makefile" have no suffix, so
        // this never collides in practice). We replicate by only consulting
        // the basename whitelist when the extension is absent OR unknown.
    }

    // Extensionless / fallback basename whitelist (case-insensitive). These
    // have an empty suffix in Python => `EXTENSION_TO_LANGUAGE.get("", "text")`
    // => "text".
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let name_lower = name.to_ascii_lowercase();
        if NON_CODE_EXTENSIONLESS_BASENAMES.contains(&name_lower.as_str()) {
            return Some("text".to_string());
        }
    }

    None
}

/// Build a single whole-file [`CodeChunk`] for a non-code file.
///
/// Returns `None` if the path is not a non-code file (per [`noncode_kind`]) or
/// the file cannot be read as UTF-8.
///
/// The chunk:
/// - has `function_name = None`, `class_name = None`, `line_start = 1`,
///   `line_end` = whole-file line count;
/// - has `content` = a char-boundary-safe preview of the first
///   [`NON_CODE_PREVIEW_CHARS`] characters, prefixed with the concise
///   filename hint (when one exists) so natural-language queries about
///   install/setup/dependencies surface well-known files (parity with
///   Python's docstring hint injected into the embedding text);
/// - has `content_hash` = MD5 of the preview (stable across rebuilds);
/// - has `doc_kind = Some(<type>)` so enrichment / call-graph passes skip it;
/// - has `language` set to a placeholder (the real type lives in `doc_kind`).
pub fn build_noncode_chunk(path: &Path) -> Option<CodeChunk> {
    let doc_kind = noncode_kind(path)?;

    let raw = std::fs::read_to_string(path).ok()?;

    // Char-boundary-safe preview cap (Python slices by chars: `content[:N]`).
    let preview: String = raw.chars().take(NON_CODE_PREVIEW_CHARS).collect();

    let line_end = raw.lines().count().max(1) as u32;

    let basename_lower = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_ascii_lowercase())
        .unwrap_or_default();
    let hint = filename_hint(&basename_lower);

    // Parity: Python injects the filename hint (docstring) into the embedding
    // text alongside the preview. The Rust live path embeds `content`
    // directly (no separate enrichment pass), so fold the hint into the
    // content here when present, mirroring that signal.
    let content = if hint.is_empty() {
        preview
    } else {
        format!("{hint}\n{preview}")
    };

    let content_hash = format!("{:x}", md5::compute(content.as_bytes()));

    // Placeholder language. Non-code chunks are never parsed (they route
    // before the `Language::from_path` gate and `doc_kind.is_some()` makes
    // every code-analysis pass skip them), so this value is metadata only.
    let language = Language::Python;

    Some(CodeChunk {
        file_path: path.to_path_buf(),
        function_name: None,
        class_name: None,
        line_start: 1,
        line_end,
        content,
        content_hash,
        language,
        doc_kind: Some(doc_kind),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn noncode_kind_recognizes_extensions() {
        assert_eq!(noncode_kind(Path::new("a.md")), Some("markdown".into()));
        assert_eq!(noncode_kind(Path::new("a.toml")), Some("toml".into()));
        assert_eq!(noncode_kind(Path::new("a.yaml")), Some("yaml".into()));
        assert_eq!(noncode_kind(Path::new("a.yml")), Some("yaml".into()));
        assert_eq!(noncode_kind(Path::new("a.json")), Some("json".into()));
        assert_eq!(noncode_kind(Path::new("a.sh")), Some("shell".into()));
        assert_eq!(noncode_kind(Path::new("a.bash")), Some("shell".into()));
        assert_eq!(noncode_kind(Path::new("a.zsh")), Some("shell".into()));
        assert_eq!(noncode_kind(Path::new("a.rst")), Some("rst".into()));
        assert_eq!(noncode_kind(Path::new("a.txt")), Some("text".into()));
    }

    #[test]
    fn noncode_kind_is_case_insensitive() {
        assert_eq!(noncode_kind(Path::new("README.MD")), Some("markdown".into()));
        assert_eq!(noncode_kind(Path::new("Config.Toml")), Some("toml".into()));
    }

    #[test]
    fn noncode_kind_extensionless_basenames() {
        assert_eq!(noncode_kind(Path::new("Makefile")), Some("text".into()));
        assert_eq!(noncode_kind(Path::new("dockerfile")), Some("text".into()));
        assert_eq!(noncode_kind(Path::new("Gemfile")), Some("text".into()));
        assert_eq!(noncode_kind(Path::new("Podfile")), Some("text".into()));
        // Nested path still matches on basename.
        assert_eq!(
            noncode_kind(Path::new("sub/dir/Makefile")),
            Some("text".into())
        );
    }

    #[test]
    fn noncode_kind_rejects_code_and_unknown() {
        assert_eq!(noncode_kind(Path::new("main.rs")), None);
        assert_eq!(noncode_kind(Path::new("app.py")), None);
        assert_eq!(noncode_kind(Path::new("image.png")), None);
        assert_eq!(noncode_kind(Path::new("noext")), None);
    }
}
