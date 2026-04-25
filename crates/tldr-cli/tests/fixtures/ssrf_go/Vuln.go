// Fixture for VAL-007 (M7): Go SSRF sink fed by a tainted source.
//
// The tldr-core taint scanner needs:
//   - a source pattern from `get_sources(Language::Go)` — we use
//     `r.URL.Query()` (HTTP query parameters) to taint variable `target`
//   - the tainted variable name appearing on the SAME line as the sink
//     pattern (the scanner does `line.contains(sink_pattern) && line.contains(var)`)
//   - a sink pattern from `get_sinks(VulnType::Ssrf, Language::Go)` —
//     post-fix this includes `http.Get(`, `http.Post(`, `http.NewRequest(`
//
// On unfixed HEAD, `get_sinks(VulnType::Ssrf, Language::Go)` returns
// `vec![]`, so the line-scanning second pass in `scan_file_vulns` never
// matches — `findings` stays empty for this fixture.

package main

import (
	"net/http"
	"strings"
)

func fetchUserTarget(r *http.Request) (*http.Response, error) {
	target := r.URL.Query().Get("url")
	// sink: http.Get( with tainted `target`
	return http.Get(target)
}

func postUserTarget(r *http.Request) (*http.Response, error) {
	target := r.URL.Query().Get("url")
	// sink: http.Post( with tainted `target`
	return http.Post(target, "application/json", strings.NewReader("{}"))
}

func newRequestUserTarget(r *http.Request) (*http.Request, error) {
	target := r.URL.Query().Get("url")
	// sink: http.NewRequest( with tainted `target`
	return http.NewRequest("GET", target, nil)
}
