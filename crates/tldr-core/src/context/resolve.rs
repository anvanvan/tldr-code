//! Context resolution layer (area: context-batch)
//!
//! Layers batch / multi-language probing / fuzzy suggestion behaviour on top
//! of the existing single-symbol [`get_relevant_context`] BFS, ported from the
//! Python reference (`tldr/api.py` `get_relevant_context_multi`,
//! `_resolve_context_languages`, `_strip_namespace_qualifier`,
//! `_first_namespace_strip`, `_fuzzy_suggest`).
//!
//! # Why a separate module
//!
//! `get_relevant_context` is the single-language, single-symbol BFS primitive.
//! The `tldr context` CLI needs three behaviours on top of it:
//!
//! 1. **Multi-language probing** — probe a list of languages in order, first
//!    hit wins. (In practice Rust's `get_relevant_context` already scans every
//!    file in the project via `scan_project_for_function`, so a single probe
//!    usually resolves cross-language; the probe loop preserves Python's
//!    first-hit-wins contract and aggregates suggestions on all-miss.)
//! 2. **Batch symbols** — resolve N symbols independently (the CLI owns the
//!    stdout/stderr split + exit-code contract; this module resolves one).
//! 3. **Fuzzy suggestions** — difflib-equivalent "Did you mean" ranking via
//!    `strsim::normalized_levenshtein >= 0.6`, top-3, bare-segment-first.
//!
//! These helpers are pure / unit-testable; the BFS itself is unchanged.

use std::path::Path;

use crate::types::Language;
use crate::{get_relevant_context, RelevantContext};

/// Namespace separators recognised by the qualified-name strip helpers.
///
/// Order matters: `"::"` is checked before `"/"` before `"."` so that the
/// rightmost match among the highest-precedence separator wins in
/// [`strip_namespace_qualifier`]. Mirrors the Python
/// `_NAMESPACE_SEPARATORS` tuple.
const NAMESPACE_SEPARATORS: &[&str] = &["::", "/", "."];

/// Languages supported by the `context` call-graph surface.
///
/// Mirrors the Python `SUPPORTED_CONTEXT_LANGUAGES` set (the 11 call-graph
/// languages). Used as the `--lang all` probe list and the `--lang auto`
/// supported-filter. Note Rust's per-language extraction additionally resolves
/// some languages Python classifies as unsupported (e.g. Kotlin) when probed
/// directly — by design we do NOT raise a `NoSupportedLanguages` diagnostic
/// (Rust's broader resolution is kept superior).
pub const SUPPORTED_CONTEXT_LANGUAGES: &[Language] = &[
    Language::Python,
    Language::TypeScript,
    Language::JavaScript,
    Language::Go,
    Language::Rust,
    Language::Php,
    Language::Swift,
    Language::Java,
    Language::Ruby,
    Language::C,
    Language::Elixir,
];

/// Outcome of a multi-language probe for a single symbol.
///
/// The CLI maps `Hit` → stdout and `Miss` → stderr (with the rendered
/// "not found / Did you mean" message), and computes the batch exit code from
/// whether any symbol produced a `Hit`.
#[derive(Debug, Clone)]
pub enum MultiContextOutcome {
    /// At least one probed language resolved the symbol.
    Hit(Box<RelevantContext>),
    /// Every probed language missed.
    Miss {
        /// The symbol that was requested.
        entry: String,
        /// Languages probed, in input order.
        probed: Vec<Language>,
        /// Fuzzy "Did you mean" suggestions (may be empty).
        suggestions: Vec<String>,
    },
}

impl MultiContextOutcome {
    /// Whether this outcome resolved the symbol.
    pub fn is_hit(&self) -> bool {
        matches!(self, MultiContextOutcome::Hit(_))
    }

    /// Render the miss as a one-line diagnostic, matching the Python shape:
    /// `Function 'NAME' not found in project (probed: a, b). Did you mean: x?`
    /// (the `Did you mean` clause is omitted when there are no suggestions).
    pub fn miss_message(&self) -> Option<String> {
        match self {
            MultiContextOutcome::Hit(_) => None,
            MultiContextOutcome::Miss {
                entry,
                probed,
                suggestions,
            } => {
                let probed_csv = probed
                    .iter()
                    .map(|l| l.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let mut msg = if probed.is_empty() {
                    format!("Function '{}' not found in project (no supported languages probed)", entry)
                } else {
                    format!("Function '{}' not found in project (probed: {})", entry, probed_csv)
                };
                if !suggestions.is_empty() {
                    msg.push_str(&format!(". Did you mean: {}?", suggestions.join(", ")));
                }
                Some(msg)
            }
        }
    }
}

/// Probe each language in `languages` order; return the first non-error hit.
///
/// Ported from Python `get_relevant_context_multi`. First-hit-wins — in
/// polyglot projects where multiple languages define the same name, the first
/// language that resolves wins. On all-miss, returns
/// [`MultiContextOutcome::Miss`] with the probed languages and the fuzzy
/// suggestions harvested from the first probe that produced any (so the CLI can
/// render a single "Did you mean" hint).
pub fn get_relevant_context_multi(
    project: &Path,
    entry_point: &str,
    depth: usize,
    languages: &[Language],
    include_docstrings: bool,
) -> MultiContextOutcome {
    if languages.is_empty() {
        return MultiContextOutcome::Miss {
            entry: entry_point.to_string(),
            probed: Vec::new(),
            suggestions: Vec::new(),
        };
    }

    let mut probed: Vec<Language> = Vec::new();
    let mut first_suggestions: Option<Vec<String>> = None;

    for &lang in languages {
        match get_relevant_context(project, entry_point, depth, lang, include_docstrings, None) {
            Ok(ctx) => return MultiContextOutcome::Hit(Box::new(ctx)),
            Err(err) => {
                probed.push(lang);
                // Harvest suggestions from the first probe that carries any.
                if first_suggestions.is_none() {
                    if let crate::error::TldrError::FunctionNotFound { suggestions, .. } = &err {
                        if !suggestions.is_empty() {
                            first_suggestions = Some(suggestions.clone());
                        }
                    }
                }
            }
        }
    }

    MultiContextOutcome::Miss {
        entry: entry_point.to_string(),
        probed,
        suggestions: first_suggestions.unwrap_or_default(),
    }
}

/// Convert a `--lang` argument + project path into the ordered list of
/// languages to probe for the `context` command.
///
/// Ported (with the `NoSupportedLanguages` branch intentionally DROPPED per
/// the area's resolved decisions) from Python `_resolve_context_languages`:
///
/// - `"all"`  → every supported context language ([`SUPPORTED_CONTEXT_LANGUAGES`]).
/// - `"auto"` → the dominant detected language (via `Language::from_directory`),
///   or `[Python]` when the project has no recognisable source files
///   (consistent with the historical default + Python's `["python"]`
///   fallback). A single probe is sufficient for cross-language resolution
///   because each per-language `get_relevant_context` probe scans the WHOLE
///   project tree (not just the requested language's extensions). Unlike
///   Python, an unsupported-only project (e.g. Kotlin) is NOT an error: the
///   detected dominant language is probed directly and Rust extracts it —
///   keeping Rust's broader resolution superior.
/// - explicit (e.g. `"rust"`) → `[that language]`.
///
/// `lang_arg` is matched case-insensitively. Returns `Err(String)` only for an
/// unrecognised explicit language token (the CLI normally pre-validates these
/// via clap, but the function is robust on its own).
pub fn resolve_context_languages(lang_arg: &str, project: &Path) -> Result<Vec<Language>, String> {
    match lang_arg.to_lowercase().as_str() {
        "all" => Ok(SUPPORTED_CONTEXT_LANGUAGES.to_vec()),
        "auto" => Ok(vec![Language::from_directory(project).unwrap_or(Language::Python)]),
        other => other.parse::<Language>().map(|l| vec![l]),
    }
}

/// Strip a qualified-name prefix and return the trailing bare segment.
///
/// Ported from Python `_strip_namespace_qualifier`. Walks the recognised
/// separators (`"::"`, `"/"`, `"."`) and picks the rightmost matching position
/// across the whole string, so `"a/b.c"` yields `"c"` and
/// `"providers/anthropic.stream"` yields `"stream"`. Returns `None` when no
/// recognised separator is present or the trailing segment would be empty.
///
/// Empty leading segments are rejected for `"."` and `"/"` (`".foo"` → `None`)
/// but ALLOWED for `"::"` (`"::foo"` → `"foo"`) so root-namespace forms like
/// `::std::vec::Vec` collapse correctly.
pub fn strip_namespace_qualifier(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let mut best_pos: i64 = -1;
    let mut best_sep = "";
    for &sep in NAMESPACE_SEPARATORS {
        if let Some(pos) = name.rfind(sep) {
            if pos as i64 > best_pos {
                best_pos = pos as i64;
                best_sep = sep;
            }
        }
    }
    if best_pos < 0 {
        return None;
    }
    let pos = best_pos as usize;
    let trailing = &name[pos + best_sep.len()..];
    if trailing.is_empty() {
        return None;
    }
    let leading = &name[..pos];
    // "::" allows empty leading (root-namespace); "." and "/" do not.
    if leading.is_empty() && best_sep != "::" {
        return None;
    }
    Some(trailing.to_string())
}

/// Return the trailing segment after the LEFTMOST applicable separator.
///
/// Ported from Python `_first_namespace_strip`. Separator precedence is
/// `"::"` → `"/"` → `"."`; the first one whose `find` succeeds is used (we then
/// take the trailing segment after the leftmost occurrence of that separator).
pub fn first_namespace_strip(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    for &sep in NAMESPACE_SEPARATORS {
        if let Some(pos) = name.find(sep) {
            let trailing = &name[pos + sep.len()..];
            let leading = &name[..pos];
            if trailing.is_empty() {
                continue;
            }
            if leading.is_empty() && sep != "::" {
                continue;
            }
            return Some(trailing.to_string());
        }
    }
    None
}

/// difflib-equivalent fuzzy suggestion ranking.
///
/// Ported from Python `_fuzzy_suggest` (which wraps
/// `difflib.get_close_matches(n=3, cutoff=0.6)`): try the fallback bare segment
/// first, then the original name; the first non-empty match list wins. Uses
/// `strsim::normalized_levenshtein` (>= `cutoff`) as the similarity score,
/// returning the top-`n` candidates ranked by descending score (ties broken by
/// candidate order for determinism). Returns an empty vec when nothing is close.
pub fn fuzzy_suggest(
    name: &str,
    fallback_name: Option<&str>,
    candidates: &[String],
) -> Vec<String> {
    fuzzy_suggest_with(name, fallback_name, candidates, 3, 0.6)
}

/// Parameterised core of [`fuzzy_suggest`] (exposed for unit tests / callers
/// needing a custom `n` / `cutoff`).
pub fn fuzzy_suggest_with(
    name: &str,
    fallback_name: Option<&str>,
    candidates: &[String],
    n: usize,
    cutoff: f64,
) -> Vec<String> {
    if let Some(fb) = fallback_name {
        if fb != name {
            let close = close_matches(fb, candidates, n, cutoff);
            if !close.is_empty() {
                return close;
            }
        }
    }
    close_matches(name, candidates, n, cutoff)
}

/// Rank `candidates` by `normalized_levenshtein(target, candidate)`, keep those
/// scoring `>= cutoff`, and return the top-`n` (descending score; stable on
/// candidate input order for ties — matching difflib's deterministic ordering).
fn close_matches(target: &str, candidates: &[String], n: usize, cutoff: f64) -> Vec<String> {
    let mut scored: Vec<(usize, f64, &String)> = candidates
        .iter()
        .enumerate()
        .map(|(i, c)| (i, strsim::normalized_levenshtein(target, c), c))
        .filter(|(_, score, _)| *score >= cutoff)
        .collect();
    // Sort by descending score; ties keep original candidate order (stable on
    // the captured index) — difflib likewise preserves first-seen order on ties.
    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });
    scored.into_iter().take(n).map(|(_, _, c)| c.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_namespace_qualifier_rightmost() {
        // Rightmost separator across the recognised set wins.
        assert_eq!(strip_namespace_qualifier("a/b.c").as_deref(), Some("c"));
        assert_eq!(
            strip_namespace_qualifier("providers/anthropic.stream").as_deref(),
            Some("stream")
        );
        assert_eq!(
            strip_namespace_qualifier("Calculator.add").as_deref(),
            Some("add")
        );
        assert_eq!(
            strip_namespace_qualifier("Engine::run").as_deref(),
            Some("run")
        );
        assert_eq!(
            strip_namespace_qualifier("sub.mod.deepfn").as_deref(),
            Some("deepfn")
        );
    }

    #[test]
    fn test_strip_namespace_qualifier_colon_allows_empty_leading() {
        // "::" allows an empty leading segment (root namespace).
        assert_eq!(strip_namespace_qualifier("::foo").as_deref(), Some("foo"));
        assert_eq!(
            strip_namespace_qualifier("::std::vec::Vec").as_deref(),
            Some("Vec")
        );
    }

    #[test]
    fn test_strip_namespace_qualifier_dot_slash_reject_empty_leading() {
        // "." and "/" do NOT allow an empty leading segment.
        assert_eq!(strip_namespace_qualifier(".foo"), None);
        assert_eq!(strip_namespace_qualifier("/foo"), None);
    }

    #[test]
    fn test_strip_namespace_qualifier_no_separator_or_empty_trailing() {
        assert_eq!(strip_namespace_qualifier("bare"), None);
        assert_eq!(strip_namespace_qualifier(""), None);
        // Trailing segment empty → None.
        assert_eq!(strip_namespace_qualifier("foo."), None);
        assert_eq!(strip_namespace_qualifier("foo::"), None);
    }

    #[test]
    fn test_first_namespace_strip_leftmost() {
        // Leftmost separator by precedence "::" > "/" > "." governs the hop.
        assert_eq!(
            first_namespace_strip("sub.mod.deepfn").as_deref(),
            Some("mod.deepfn")
        );
        assert_eq!(
            first_namespace_strip("a/b/c").as_deref(),
            Some("b/c")
        );
        assert_eq!(
            first_namespace_strip("A::B::C").as_deref(),
            Some("B::C")
        );
        assert_eq!(first_namespace_strip("bare"), None);
    }

    #[test]
    fn test_fuzzy_suggest_finds_transposition_typo() {
        // The real fuzzy-quality gap: a transposition/missing-char typo that a
        // substring matcher misses but difflib (cutoff 0.6) still suggests.
        let cands = vec![
            "compute".to_string(),
            "helper".to_string(),
            "add".to_string(),
        ];
        assert_eq!(fuzzy_suggest("compyte", None, &cands), vec!["compute"]);
        assert_eq!(fuzzy_suggest("helpr", None, &cands), vec!["helper"]);
    }

    #[test]
    fn test_fuzzy_suggest_cutoff_holds_for_nothing_close() {
        let cands = vec!["compute".to_string(), "helper".to_string()];
        assert!(fuzzy_suggest("nonexistent_xyz", None, &cands).is_empty());
    }

    #[test]
    fn test_fuzzy_suggest_top_n_limit() {
        // More than 3 close candidates → only top 3 returned.
        let cands = vec![
            "compute".to_string(),
            "computer".to_string(),
            "computed".to_string(),
            "computes".to_string(),
            "computing".to_string(),
        ];
        let got = fuzzy_suggest("compute", None, &cands);
        assert!(got.len() <= 3, "expected <=3 suggestions, got {:?}", got);
        // Exact match must rank first.
        assert_eq!(got[0], "compute");
    }

    #[test]
    fn test_fuzzy_suggest_bare_segment_tried_before_original() {
        // fallback (bare) segment is tried first; if it matches, those win even
        // when the original name would also match something.
        let cands = vec!["deepfn".to_string(), "shallow".to_string()];
        // original "sub.mod.deepfn" has no close match; bare "deepfn" does.
        let got = fuzzy_suggest("sub.mod.deepfn", Some("deepfn"), &cands);
        assert_eq!(got, vec!["deepfn"]);
    }

    #[test]
    fn test_resolve_context_languages_all() {
        let langs = resolve_context_languages("all", Path::new(".")).unwrap();
        assert_eq!(langs, SUPPORTED_CONTEXT_LANGUAGES.to_vec());
    }

    #[test]
    fn test_resolve_context_languages_explicit() {
        assert_eq!(
            resolve_context_languages("rust", Path::new(".")).unwrap(),
            vec![Language::Rust]
        );
        assert_eq!(
            resolve_context_languages("Python", Path::new(".")).unwrap(),
            vec![Language::Python]
        );
    }

    #[test]
    fn test_resolve_context_languages_explicit_unknown_errors() {
        assert!(resolve_context_languages("klingon", Path::new(".")).is_err());
    }
}
