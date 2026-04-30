# workspace-test-infrastructure-v1 — M5 Release Prep

**Internal milestone — NOT externally published.**
**Tag:** `workspace-test-infrastructure-v1` (annotated, local-only).
**Tag points at:** `64e1943` (M5 CHANGELOG commit).
**Date sealed:** 2026-04-30.

---

## 1. Milestone scope summary

Hygiene milestone — penultimate before external publish. Restores
`cargo test --workspace --features semantic` baseline (modulo 35
documented Cat-B carry-forwards owned by sibling milestone
`vuln-source-parity-v1`).

No new features, no new test coverage, no public API changes. Pure
test-infrastructure cleanup of dangling CLI test invocations against
archived subcommands (legacy from prior internal milestones that moved
implementations to `crates/tldr-cli/src/commands/archived/` but did not
delete the corresponding test invocations) plus orthogonal real-world
test failures unrelated to vuln source-bank gaps.

---

## 2. Actual LOC delta (sourced, not estimated)

`git diff --stat HEAD~8 HEAD -- ':!continuum/'` — covers M1 through M4
source-tree changes (excluding plan-dir bookkeeping):

```
33 files changed, 378 insertions(+), 4655 deletions(-)
```

Net delta: **−4277 LOC across 33 files** (workspace-source only;
plan-dir docs excluded).

Per-file breakdown (top contributors, deletions):

| File | Lines |
|------|------:|
| `crates/tldr-cli/tests/p2_multilang_tests.rs`             | −1110 |
| `crates/tldr-cli/tests/ssa_cli_tests.rs`                  |  −660 |
| `crates/tldr-cli/tests/remaining_test.rs`                 |  −575 |
| `crates/tldr-cli/tests/cli_remaining_tests.rs`            |  −491 |
| `crates/tldr-cli/tests/patterns_test.rs`                  |  −463 |
| `crates/tldr-cli/tests/cli_graph_tests.rs`                |  −370 |
| `crates/tldr-cli/tests/contracts_test.rs`                 |  −283 |
| `crates/tldr-cli/tests/cli_patterns_contracts_tests.rs`   |  −240 (net) |
| `crates/tldr-cli/tests/gvn_cli_tests.rs`                  |  −212 |
| `crates/tldr-cli/tests/cli_search_context_tests.rs`       |  −199 (net) |

M2 / M4 source edits (smaller, surgical):

| File | Lines (net) |
|------|------------:|
| `crates/tldr-core/src/metrics/cognitive.rs`              |   ~88 |
| `crates/tldr-core/src/quality/coverage.rs`               |   ~55 |
| `crates/tldr-cli/tests/cli_tests.rs`                     |  ~−64 |
| `crates/tldr-core/tests/language_parity_test.rs`         |  ~−31 |
| `crates/tldr-core/tests/quality_tests.rs`                |   ~27 |
| `crates/tldr-core/src/surface/typescript.rs`             |   ~25 |
| `crates/tldr-core/src/git/mod.rs`                        |   ~11 |
| `crates/tldr-core/src/quality/dead_code.rs`              |   ~11 |
| `crates/tldr-core/src/quality/martin.rs`                 |    ~9 |
| `crates/tldr-core/tests/fixtures/empty-dir/.gitkeep`     |     0 (new fixture file) |

Plus minor edits in `bench_surface_search_multilang.rs`, `fs_tests.rs`,
`reaching_defs_cli_tests.rs`, `val013_daemon_status_cross_cwd_test.rs`,
`val010_change_impact_git_path_test.rs`,
`smells_pr_focused_filter_test.rs`, `cli_quality_tests.rs`,
`bugbot/text_format.rs`, `daemon/daemon_registry.rs`.

---

## 3. Actual test count comparison (sourced from commit stats)

### Archived-cmd tests deleted (M3, commit `cf0b2be`)

| Bucket | Count |
|--------|------:|
| Whole-file deletions (`ssa_cli_tests.rs` 26 + `gvn_cli_tests.rs` 9) | 35 |
| Surgical per-test deletions across 8 mixed files | 127 |
| **Total archived-cmd CLI tests removed** | **162** |

Mixed-file targets (M3 surgical deletes): `cli_graph_tests.rs`,
`cli_patterns_contracts_tests.rs`, `cli_remaining_tests.rs`,
`cli_tests.rs`, `contracts_test.rs`, `p2_multilang_tests.rs`,
`patterns_test.rs`, `remaining_test.rs`.

False-positives from M1 enumeration explicitly preserved in M3 (3):
- `test_debt_category_maintainability` (`--category maintainability` is
  VALUE for active `debt`, not archived `maintainability` subcmd)
- `test_explain_json_schema` (`purity` is JSON schema FIELD in active
  `explain` response)
- `test_api_check_no_findings_clean_code` (body invokes only active
  `api-check`)

### Doctest failures fixed (M2, commit `d17a24c`)

| Site | Fix |
|------|-----|
| `callgraph::cross_file_types::FuncIndexProxy` | Doctest rewritten to use `FuncIndexProxyMut` (working impl) — `FuncIndexProxy` is `unimplemented!()` stub at L1109 |
| `callgraph::languages::kotlin::KotlinHandler::parse_import_node` | Bare ` ``` ` → ` ```text ` fence (pseudo-grammar, not Rust) |
| `callgraph::languages::luau::LuauHandler::extract_aliased_require` | Bare ` ``` ` → ` ```text ` fence (pseudo-grammar, not Rust) |
| `surface::triggers::extract_name_triggers` | Stale import path `tldr_core::contracts::triggers::...` → `tldr_core::surface::triggers::...` |

**Total doctest fixes: 4.**

### Cat-C orthogonal-real failures fixed (M4, commit `68058a5`)

Per `M4-report.json` and `M4-fix-by-fix-capture.json`:

| Subclass | Count |
|----------|------:|
| Named-exception source-code edits (cognitive `else`, `git_log`, empty-input handlers, coverage parser, change-impact `NoBaseline` reason) | 5 |
| Test-fixture corrections (numeric drift, schema field updates, similarity threshold, etc.) | 22 |
| DELETE-on-stale entries (Kotlin/Swift `*_returns_unsupported` + 6 others) | 8 |
| Already-green at start of M4 | 2 |
| Empty-directory fixture gap creation (`.gitkeep`) | 1 |
| **Total Cat-C closures** | **38** |

Plus 2 entries reclassified Cat-C → Cat-B per
`operator-escalation-regression.json` (Option A applied):
- `test_vuln_detects_xss` — Python Flask f-string return (HtmlOutput
  sink coverage gap, absorbed into vuln-source-parity-v1)
- `ruby_io_popen_with_user_input_via_compute_taint` — FAI-v1 M5
  bare-`gets` carry-forward (regex `\bgets\b` retained per Option A;
  `analyze_ast_only` test harness short-circuits regex bank)

These 2 reclassifications raise the Cat-B carry-forward count from the
contract's stated 33 to the final **35 EXACTLY**.

### Final test verification

| Command | Result |
|---------|--------|
| `cargo test --workspace --features semantic --no-fail-fast --release` | **35 failures EXACTLY** (all Cat-B vuln-source-parity-v1 carry-forwards) |
| `cargo test --workspace --features semantic --doc --no-fail-fast` | 0 failures |
| `cargo build --workspace --tests --features semantic` | exit 0 |
| `cargo clippy --workspace --tests --features semantic -- -D warnings` | exit 0 |

---

## 4. Tags state post-milestone

**7 internal tags applied locally — NONE pushed:**

| Tag | Purpose |
|-----|---------|
| `engine-v1`                          | Engine-v1 internal milestone |
| `quality-v1`                         | Quality-v1 internal milestone |
| `regex-removal-v1`                   | Regex-driven dispatch removal |
| `field_access_info-extension-v1`     | FAI-v1 extension milestone |
| `sanitizer-removal-v1`               | Sanitizer regex-free dispatch |
| `vuln-migration-v1`                  | `tldr vuln` canonical-engine migration |
| `workspace-test-infrastructure-v1`   | **THIS milestone (M5 just sealed)** |

Plus the public-release tags (`v0.1.x` / `v0.2.x`) applied by prior
publish operations — orthogonal to this internal-milestone tag chain.

**Internal-versioning posture honored throughout:**
- NO `git push` of any kind for any of the 7 internal tags.
- NO `cargo publish`.
- NO version bumps in any `Cargo.toml` manifest.

---

## 5. Next steps

### 5.1 vuln-source-parity-v1 sibling milestone (in progress)

Owns the 35 Cat-B carry-forwards. Scope: AST sink-bank extension across
`LanguagePatterns` for source-bank-gap RED tests across
Go/Java/CSharp/Scala/Lua/Elixir × multiple vuln types, plus the 2
Option-A reclassifications (Python Flask f-string XSS shape; Ruby
bare-`gets` follow-on out-of-scope into future
`ruby-bare-call-extraction-v1`).

When sibling milestone seals: `cargo test --workspace --features
semantic --no-fail-fast --release` reaches 0 failures (modulo any
newly-introduced regressions that appear after the sibling closes).

### 5.2 Publish-operator binary verification gate

After BOTH this milestone AND vuln-source-parity-v1 land:
1. Publish-operator runs `pre-publish-binary-verification.json`
   protocol (vuln-v1 M6 artifact).
2. On verdict PASS: single coherent external `cargo publish`
   ships, closing:
   - Issue #7 (callgraph)
   - Issue #23 (Rust trait `FuncDef`)
   - Issue #24 (string-literal substring FP, ALL paths)
   - Issue #27 (cache cross-contamination)
   - Issue #28 (daemon language threading)
   - `tldr vuln` FP class (closed end-to-end via vuln-migration-v1)
   - Sanitizer correctness (closed via sanitizer-removal-v1)

Single release commit with appropriate version bump occurs THEN
(downstream of all 7 internal tags), gated entirely on the binary
verification artifact.

---

## 6. Premortem outcomes (retrospective)

Premortem caught 1 critical blocker + 2 strengthening conditions
pre-/autonomous. All 3 amended into the dispatch contract before
launch:

1. **CRITICAL BLOCKER:** search-vs-SmartSearch disambiguation —
   `tldr search ...` invocations would have been falsely deleted as
   archived. Premortem identified that `search` is the ACTIVE
   SmartSearch CLI alias per `#[command(name = "search")]` at
   `main.rs:141-142`. Amendment: hard-coded preserve list of `search`
   variants in M3 deletion script.
2. **STRENGTHENING:** enumeration authority — premortem flagged that
   M1 enumeration must be authoritative for M3 deletion. Amendment:
   M3 must operate strictly off the M1 enumeration JSON, with
   per-test verification that the test target is in M1 enumeration.
3. **STRENGTHENING:** mixed-file per-test delete pattern — premortem
   flagged that surgical per-test deletion across 8 mixed files
   requires careful tokenization (Rust raw strings can span lines and
   contain brace chars). Amendment: M3 deletion script must properly
   tokenize raw-string state with N-hash matching across line
   boundaries.

**Honest mid-flow recovery:** M3 worker's first deletion-script attempt
mishandled raw-string state across lines (per item 3 above — strengthening
condition was correct but initial implementation missed it). Worker
escalated; orchestrator authorized working-tree restore; corrected
script properly tokenized raw-string state. Final M3 commit `cf0b2be`
landed cleanly with all 162 deletions verified.

---

## 7. Coherence with other internal milestones

| Internal milestone | Closes |
|--------------------|--------|
| `engine-v1`                          | Engine baseline (callgraph V2, etc.) |
| `quality-v1`                         | Quality metrics baseline |
| `regex-removal-v1`                   | Regex sources/sinks elimination, taint path |
| `field_access_info-extension-v1`     | FAI extension (Ruby bare-`gets` Option A applied) |
| `sanitizer-removal-v1`               | Sanitizer regex-free dispatch (`detect_sanitizer_ast` wired) |
| `vuln-migration-v1`                  | `tldr vuln` → canonical engine; closes-#24 string-literal FP class end-to-end |
| `workspace-test-infrastructure-v1`   | **THIS** — restores test baseline modulo Cat-B carry-forwards |
| `vuln-source-parity-v1` (in flight)  | 35 Cat-B carry-forwards |

After the sibling lands, the canonical
`tldr-core/security/taint.rs` is the SINGLE SOURCE OF TRUTH for taint
flow detection across both `tldr taint` and `tldr vuln`, and the test
baseline is fully restored, ready for the publish-operator binary
verification gate.

---

**End of M5 release-prep summary.**
