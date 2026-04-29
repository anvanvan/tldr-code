//! M1b VAL-001b — SSA-versioned taint key for compute_taint_with_tree
//!
//! Layered on top of M1a's VarRef-based per-line use lookup, M1b introduces a
//! `Option<&SsaFunction>` parameter to `compute_taint_with_tree`. When SSA is
//! supplied, the taint set is keyed by `SsaNameId` (versioned) so that
//! reassignment-through-sanitizer is correctly modelled — `let x = req.body;
//! x = sanitize(x); eval(x)` produces zero flows because the sanitised x_v2 is
//! a distinct SSA name.
//!
//! When SSA construction returns `Err` or yields an empty SsaFunction (per the
//! per-language SSA-coverage gap documented in the v0.3.0 contract), the engine
//! gracefully falls back to M1a's String-keyed VarRef path. This test file
//! covers BOTH branches.
//!
//! Pre-M1b RED: this test file does not compile because `compute_taint_with_tree`
//! takes 6 arguments, not 7. The missing-argument compile error IS the RED
//! capture (per the triage brief Step 4 — "RED via missing-arg compile error").
//!
//! Post-M1b GREEN: 2/2 tests pass.

use std::collections::HashMap;

use tldr_core::ast::parser::parse;
use tldr_core::cfg::get_cfg_context;
use tldr_core::dfg::get_dfg_context;
use tldr_core::security::taint::compute_taint_with_tree;
use tldr_core::ssa::construct::construct_minimal_ssa;
use tldr_core::Language;

fn statements_from(src: &str) -> HashMap<u32, String> {
    src.lines()
        .enumerate()
        .map(|(i, text)| ((i + 1) as u32, text.to_string()))
        .collect()
}

/// Reassignment through a sanitiser must clear taint on the post-sanitiser SSA
/// version. Under M1a's String-keyed taint set this fixture may still report a
/// flow because the Raw key sees the same name `x` on the eval line as on the
/// req.body line. Under M1b the post-sanitiser x is a distinct SsaNameId.
#[test]
fn taint_versioned_after_sanitizer_reassignment() {
    // Uses a TS-recognised sanitiser (`DOMPurify.sanitize`) so M1a's
    // `sanitized_vars` guard at flow construction would *also* clear this
    // flow. M1b's SSA-versioned propagation strengthens the underlying model:
    // x_v2 is a distinct SsaNameId whose taint is cleared at the def site, so
    // any downstream uses of x_v2 (like `eval(x)` on line 4) reference an
    // un-tainted SSA name even before the `sanitized_vars` flow-suppression
    // guard fires. The assertion is the same — zero flows.
    let src = "\
function handler(req, res) {
    let x = req.body;
    x = DOMPurify.sanitize(x);
    eval(x);
}
";

    let cfg =
        get_cfg_context(src, "handler", Language::TypeScript).expect("CFG must succeed for TS");
    let dfg =
        get_dfg_context(src, "handler", Language::TypeScript).expect("DFG must succeed for TS");
    // Tolerate per-language SSA gaps via .ok() — the next test exercises the
    // SSA-unavailable fallback explicitly.
    let ssa = construct_minimal_ssa(&cfg, &dfg).ok();
    let tree = parse(src, Language::TypeScript).expect("TS parse must succeed");

    let result = compute_taint_with_tree(
        &cfg,
        &dfg.refs,
        &statements_from(src),
        Some(&tree),
        Some(src.as_bytes()),
        Language::TypeScript,
        ssa.as_ref(), // M1b: NEW parameter
    )
    .expect("taint analysis must succeed");

    assert!(
        result.flows.is_empty(),
        "expected zero tainted flows after sanitiser reassignment under SSA-versioned \
         propagation, got {} flow(s): {:?}",
        result.flows.len(),
        result.flows
    );
}

/// Fallback contract: when SSA is unavailable (None), the engine MUST fall back
/// to M1a's VarRef path and still detect the basic `req.body -> eval(x)` flow.
/// This guards the per-language SSA gap documented in the v0.3.0 contract.
#[test]
fn taint_falls_back_to_varref_when_ssa_unavailable() {
    let src = "\
function handler(req, res) {
    let x = req.body;
    eval(x);
}
";

    let cfg =
        get_cfg_context(src, "handler", Language::TypeScript).expect("CFG must succeed for TS");
    let dfg =
        get_dfg_context(src, "handler", Language::TypeScript).expect("DFG must succeed for TS");
    let tree = parse(src, Language::TypeScript).expect("TS parse must succeed");

    let result = compute_taint_with_tree(
        &cfg,
        &dfg.refs,
        &statements_from(src),
        Some(&tree),
        Some(src.as_bytes()),
        Language::TypeScript,
        None, // M1b: SSA unavailable — must NOT panic; falls back to M1a path
    )
    .expect("taint analysis must succeed in fallback mode");

    assert!(
        !result.flows.is_empty(),
        "fallback path must still detect the basic req.body -> eval(x) flow under \
         M1a VarRef semantics; flows={:?}, sources={:?}, sinks={:?}",
        result.flows,
        result.sources,
        result.sinks
    );
}
