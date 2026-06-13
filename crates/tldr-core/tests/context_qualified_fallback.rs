//! context-batch (area 4): the qualified-name strip-and-retry hop.
//!
//! NARROWED scope (per resolved decisions / e2e §5): the hop fixes ONLY the
//! dotted module/path forms (`module.func`, `pkg.mod.func`,
//! `sub.mod.deepfn`) and the cross-convention `Struct.method` dot form
//! (`Engine.run` resolving via the Rust-graph `Engine::run`). It must NOT
//! change the already-working `Class.method` / `Class::method` / bare-suffix
//! forms — those resolve before the hop is reached. We assert the
//! already-working forms FIRST (current-behavior guards), then the new ones,
//! then the no-phantom-stub guarantee.

use std::fs;

use tldr_core::{get_relevant_context, Language};
use tempfile::TempDir;

fn python_project() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("calc.py"),
        r#"def helper(x):
    return x + 1

def compute(x):
    return helper(x) * 2

class Calculator:
    def add(self, a, b):
        return compute(a) + compute(b)
"#,
    )
    .unwrap();
    dir
}

fn rust_project() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("lib.rs"),
        r#"fn helper_rs(x: i32) -> i32 {
    x + 1
}

fn compute_rs(x: i32) -> i32 {
    helper_rs(x) * 2
}

struct Engine;

impl Engine {
    fn run(&self) -> i32 {
        compute_rs(5)
    }
}
"#,
    )
    .unwrap();
    dir
}

fn path_qualified_project() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join("sub")).unwrap();
    fs::write(
        dir.path().join("sub/mod.py"),
        "def deepfn(x):\n    return x * 3\n",
    )
    .unwrap();
    dir
}

// ---------------------------------------------------------------------------
// Current-behavior guards: these already resolve WITHOUT the hop.
// ---------------------------------------------------------------------------

#[test]
fn bare_name_already_resolves() {
    let dir = python_project();
    let ctx = get_relevant_context(dir.path(), "add", 1, Language::Python, false, None).unwrap();
    assert!(ctx.functions.iter().any(|f| f.name.ends_with("add")));
}

#[test]
fn class_dot_method_already_resolves() {
    let dir = python_project();
    let ctx =
        get_relevant_context(dir.path(), "Calculator.add", 1, Language::Python, false, None)
            .unwrap();
    assert!(ctx.functions.iter().any(|f| f.name.ends_with("add")));
}

#[test]
fn rust_native_colon_method_already_resolves() {
    let dir = rust_project();
    let ctx =
        get_relevant_context(dir.path(), "Engine::run", 1, Language::Rust, false, None).unwrap();
    assert!(ctx.functions.iter().any(|f| f.name.ends_with("run")));
}

// ---------------------------------------------------------------------------
// New behavior: the narrowed strip-and-retry hop.
// ---------------------------------------------------------------------------

#[test]
fn cross_convention_struct_dot_method_resolves_via_hop() {
    // `Engine.run` (dot form) — the Rust call graph stores `Engine::run`, so
    // the dot form misses the edge matcher and falls into the hop, which
    // strips to bare `run` and resolves via the project scan.
    let dir = rust_project();
    let ctx = get_relevant_context(dir.path(), "Engine.run", 1, Language::Rust, false, None);
    assert!(
        ctx.is_ok(),
        "Engine.run should resolve via the strip-and-retry hop: {:?}",
        ctx.err()
    );
    let ctx = ctx.unwrap();
    assert!(
        ctx.functions.iter().any(|f| f.name.ends_with("run")),
        "expected `run` in resolved functions: {:?}",
        ctx.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
}

#[test]
fn module_dot_func_resolves_via_hop() {
    // `calc.compute` — module-qualified dot form.
    let dir = python_project();
    let ctx = get_relevant_context(dir.path(), "calc.compute", 1, Language::Python, false, None);
    assert!(
        ctx.is_ok(),
        "calc.compute should resolve via the hop: {:?}",
        ctx.err()
    );
    assert!(ctx
        .unwrap()
        .functions
        .iter()
        .any(|f| f.name.ends_with("compute")));
}

#[test]
fn path_qualified_pkg_mod_func_resolves_via_hop() {
    // `sub.mod.deepfn` — pkg.mod.func form. The hop strips to bare `deepfn`.
    let dir = path_qualified_project();
    let ctx =
        get_relevant_context(dir.path(), "sub.mod.deepfn", 1, Language::Python, false, None);
    assert!(
        ctx.is_ok(),
        "sub.mod.deepfn should resolve via the hop: {:?}",
        ctx.err()
    );
    assert!(ctx
        .unwrap()
        .functions
        .iter()
        .any(|f| f.name.ends_with("deepfn")));

    // And the single-hop `mod.deepfn` form too.
    let ctx2 = get_relevant_context(dir.path(), "mod.deepfn", 1, Language::Python, false, None);
    assert!(ctx2.is_ok(), "mod.deepfn should resolve via the hop: {:?}", ctx2.err());
}

// ---------------------------------------------------------------------------
// No phantom stub on a genuine miss.
// ---------------------------------------------------------------------------

#[test]
fn missing_symbol_errors_without_phantom_stub() {
    let dir = python_project();
    let ctx = get_relevant_context(
        dir.path(),
        "totally_absent_symbol",
        2,
        Language::Python,
        false,
        None,
    );
    assert!(ctx.is_err(), "a missing top-level entry must error, not stub");
}
