//! M3 VAL-003 — TS taint patterns for Next.js / Fastify / NestJS (#1.F)
//!
//! Pre-fix RED: each framework fixture (Next.js, Fastify, NestJS) returns
//! `sources.is_empty() && sinks.is_empty() && flows.is_empty()` because
//! TYPESCRIPT_PATTERNS at `taint.rs:450-487` is Express-only.
//!
//! Post-fix GREEN: each fixture yields `>= 1 source AND >= 1 sink AND >= 1 flow`.
//!
//! Express regression guard: existing `req.body -> eval(...)` Express pattern
//! still produces a flow (must hold both before and after the fix).

use std::collections::HashMap;

use tldr_core::ast::parser::parse;
use tldr_core::cfg::get_cfg_context;
use tldr_core::dfg::get_dfg_context;
use tldr_core::security::taint::compute_taint_with_tree;
use tldr_core::security::taint::TaintInfo;
use tldr_core::Language;

/// Build a `TaintInfo` for a TypeScript fixture by parsing the source, building
/// CFG + DFG for the named function, and running `compute_taint_with_tree`.
fn analyze_ts(src: &str, function_name: &str) -> TaintInfo {
    let cfg = get_cfg_context(src, function_name, Language::TypeScript)
        .expect("CFG extraction must succeed for fixture");
    let dfg = get_dfg_context(src, function_name, Language::TypeScript)
        .expect("DFG extraction must succeed for fixture");
    let tree = parse(src, Language::TypeScript).expect("TS parse must succeed for fixture");

    // line -> statement string (1-indexed line numbers)
    let statements: HashMap<u32, String> = src
        .lines()
        .enumerate()
        .map(|(i, line)| ((i + 1) as u32, line.to_string()))
        .collect();

    compute_taint_with_tree(
        &cfg,
        &dfg.refs,
        &statements,
        Some(&tree),
        Some(src.as_bytes()),
        Language::TypeScript,
    )
    .expect("taint analysis must succeed for fixture")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — Next.js App Router route handler
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn taint_nextjs_route_handler_finds_flow() {
    let src = r#"
import { NextRequest, NextResponse } from 'next/server';

export async function POST(request) {
    const data = await request.json();
    eval(data.code);
    return NextResponse.json({ ok: true });
}
"#;
    let info = analyze_ts(src, "POST");
    assert!(
        !info.sources.is_empty(),
        "Next.js: expected >= 1 source, got 0 (request.json() must match NEXTJS_PATTERNS); \
         sources={:?}",
        info.sources
    );
    assert!(
        !info.sinks.is_empty(),
        "Next.js: expected >= 1 sink, got 0 (eval() must match); sinks={:?}",
        info.sinks
    );
    assert!(
        !info.flows.is_empty(),
        "Next.js: expected >= 1 flow, got 0 (request.json() -> eval() must produce a flow); \
         flows={:?}",
        info.flows
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — Fastify handler (request.body -> eval)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn taint_fastify_handler_finds_flow() {
    let src = r#"
import Fastify from 'fastify';

async function fastifyEcho(request, reply) {
    const cmd = request.body.cmd;
    eval(cmd);
    reply.send({ ok: true });
}
"#;
    let info = analyze_ts(src, "fastifyEcho");
    assert!(
        !info.sources.is_empty(),
        "Fastify: expected >= 1 source, got 0 (request.body must match FASTIFY_PATTERNS); \
         sources={:?}",
        info.sources
    );
    assert!(
        !info.sinks.is_empty(),
        "Fastify: expected >= 1 sink, got 0 (eval() must match); sinks={:?}",
        info.sinks
    );
    assert!(
        !info.flows.is_empty(),
        "Fastify: expected >= 1 flow, got 0 (request.body -> eval() must produce a flow); \
         flows={:?}",
        info.flows
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — NestJS controller via @Req() request: Request manual access
// ─────────────────────────────────────────────────────────────────────────────
//
// Per scout deepdive: decorator-injected parameters `(@Body() body: T)` are
// invisible to the regex engine. Coverage focuses on `@Req()` / manual
// `request.body` access patterns. Fixture is a free function emulating the
// hand-unwrapped form a NestJS dev would write inside a `@Req()` handler.

#[test]
fn taint_nestjs_controller_finds_flow() {
    let src = r#"
import { Controller, Post, Req } from '@nestjs/common';

async function nestCreate(request) {
    const body = request.body;
    eval(body.script);
    return { ok: true };
}
"#;
    let info = analyze_ts(src, "nestCreate");
    assert!(
        !info.sources.is_empty(),
        "NestJS: expected >= 1 source, got 0 (request.body must match NESTJS_PATTERNS); \
         sources={:?}",
        info.sources
    );
    assert!(
        !info.sinks.is_empty(),
        "NestJS: expected >= 1 sink, got 0 (eval() must match); sinks={:?}",
        info.sinks
    );
    assert!(
        !info.flows.is_empty(),
        "NestJS: expected >= 1 flow, got 0 (request.body -> eval() must produce a flow); \
         flows={:?}",
        info.flows
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4 — Express regression guard (must pass on HEAD pre-fix AND post-fix)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn taint_express_still_works_regression_guard() {
    let src = r#"
const express = require('express');

function expressRun(req, res) {
    const code = req.body.code;
    eval(code);
    res.send('ok');
}
"#;
    let info = analyze_ts(src, "expressRun");
    assert!(
        !info.sources.is_empty(),
        "REGRESSION: Express req.body must remain a source; sources={:?}",
        info.sources
    );
    assert!(
        !info.sinks.is_empty(),
        "REGRESSION: Express eval() must remain a sink; sinks={:?}",
        info.sinks
    );
    assert!(
        !info.flows.is_empty(),
        "REGRESSION: Express req.body -> eval() must remain a flow; flows={:?}",
        info.flows
    );
}
