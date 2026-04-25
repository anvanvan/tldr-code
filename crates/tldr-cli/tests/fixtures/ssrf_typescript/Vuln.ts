// Fixture for VAL-007 (M7): TypeScript SSRF sink fed by a tainted source.
//
// The tldr-core taint scanner needs:
//   - a source pattern from `get_sources(Language::TypeScript)` — we use
//     `req.query` (Express query parameter) to taint variable `target`
//   - the tainted variable name appearing on the SAME line as the sink
//     pattern (the scanner does `line.contains(sink_pattern) && line.contains(var)`)
//   - a sink pattern from `get_sinks(VulnType::Ssrf, Language::TypeScript)` —
//     post-fix this includes `fetch(`, `axios.get(`, `axios.post(`,
//     `http.get(`, `http.request(`
//
// On unfixed HEAD, `get_sinks(VulnType::Ssrf, Language::TypeScript)` returns
// `vec![]`, so the line-scanning second pass in `scan_file_vulns` never
// matches — `findings` stays empty for this fixture.

import axios from "axios";
import * as http from "http";

export async function fetchUserTarget(req: any) {
  const target = req.query.url;
  // sink: fetch( with tainted `target`
  return await fetch(target);
}

export async function axiosGetUserTarget(req: any) {
  const target = req.query.url;
  // sink: axios.get( with tainted `target`
  return await axios.get(target);
}

export async function axiosPostUserTarget(req: any) {
  const target = req.query.url;
  // sink: axios.post( with tainted `target`
  return await axios.post(target, { a: 1 });
}

export function httpGetUserTarget(req: any) {
  const target = req.query.url;
  // sink: http.get( with tainted `target`
  return http.get(target, () => {});
}

export function httpRequestUserTarget(req: any) {
  const target = req.query.url;
  // sink: http.request( with tainted `target`
  return http.request(target, () => {});
}
