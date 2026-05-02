//! Canonical function enumerator (canonical-function-enumerator-v1)
//!
//! Single source of truth for "how many functions are in this codebase". Used
//! by `health.summary.functions_analyzed`, `structure` (via the same
//! `extract_file` data flow), and `dead.total_functions` so that all three
//! commands report identical counts on the same input.
//!
//! # Inclusion policy (canonical)
//!
//! A "function" for canonical-count purposes is anything that
//! `crate::ast::extract::extract_file` surfaces in either
//! `ModuleInfo.functions` (top-level) or `ClassInfo.methods` (class members).
//! Concretely this includes:
//!
//! - All top-level `def` / `function` / `fn` / `func` declarations.
//! - All class methods (including dunder methods like `__init__`).
//! - All assigned function-expression / arrow-function values from
//!   `js-extract-function-expressions-v1` (e.g. `const f = () => {}`,
//!   `const f = function() {}`).
//!
//! It does NOT include:
//!
//! - Anonymous lambdas / inline arrow callbacks not bound to a name.
//! - Computed-property method names that the AST extractor cannot resolve to
//!   a stable string identifier.
//! - Decorated stubs without a body (function declarations with no body node).
//!
//! # Out of scope
//!
//! `verify` reports `coverage.total_functions`, which counts only
//! contract-amenable functions (those with extractable pre/postconditions).
//! That is a deliberately *different* metric and is not unified here.

use std::path::{Path, PathBuf};

use crate::types::{Language, ModuleInfo};
use crate::walker::walk_project;

use super::extract::extract_file;

/// Count functions canonically across a path.
///
/// Walks `path` (or treats it as a single file), parses every file matching
/// `language`'s extensions via `extract_file`, and returns the sum of
/// `ModuleInfo.functions.len() + sum(ClassInfo.methods.len())`.
///
/// Files that fail to parse are silently skipped (consistent with
/// `dead_code` and `health` enumeration behavior).
pub fn count_functions_canonical(path: &Path, language: Language) -> u32 {
    let module_infos = collect_module_infos(path, language);
    count_functions_canonical_from_modules(&module_infos)
}

/// Count functions canonically from already-extracted module infos.
///
/// Avoids re-parsing when callers have already run `extract_file` over the
/// project. Sums `info.functions.len() + sum(class.methods.len())` across
/// every module.
pub fn count_functions_canonical_from_modules(module_infos: &[(PathBuf, ModuleInfo)]) -> u32 {
    let mut total: u32 = 0;
    for (_, info) in module_infos {
        total = total.saturating_add(info.functions.len() as u32);
        for class in &info.classes {
            total = total.saturating_add(class.methods.len() as u32);
        }
    }
    total
}

fn collect_module_infos(path: &Path, language: Language) -> Vec<(PathBuf, ModuleInfo)> {
    let mut module_infos: Vec<(PathBuf, ModuleInfo)> = Vec::new();

    if path.is_file() {
        if let Ok(info) = extract_file(path, path.parent()) {
            module_infos.push((path.to_path_buf(), info));
        }
        return module_infos;
    }

    let extensions = language.extensions();
    for entry in walk_project(path) {
        let file_path = entry.path();
        if !file_path.is_file() {
            continue;
        }
        let Some(ext) = file_path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        let ext_with_dot = format!(".{}", ext);
        if !extensions.contains(&ext_with_dot.as_str()) {
            continue;
        }
        if let Ok(info) = extract_file(file_path, Some(path)) {
            module_infos.push((file_path.to_path_buf(), info));
        }
    }
    module_infos
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn empty_dir_zero() {
        let dir = tempdir().unwrap();
        assert_eq!(count_functions_canonical(dir.path(), Language::Python), 0);
    }

    #[test]
    fn python_top_level_and_methods() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("m.py");
        fs::write(
            &p,
            "def a():\n    pass\n\ndef b():\n    pass\n\nclass C:\n    def m1(self):\n        pass\n    def m2(self):\n        pass\n",
        )
        .unwrap();
        // 2 top-level + 2 methods = 4
        assert_eq!(count_functions_canonical(dir.path(), Language::Python), 4);
    }

    #[test]
    fn rust_fns_and_impl_methods() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("m.rs");
        fs::write(
            &p,
            "fn top1() {}\nfn top2() {}\nstruct S;\nimpl S { fn m1(&self) {} fn m2(&self) {} }\n",
        )
        .unwrap();
        // 2 top-level + 2 impl methods = 4
        assert_eq!(count_functions_canonical(dir.path(), Language::Rust), 4);
    }
}
