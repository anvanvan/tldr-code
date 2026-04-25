# Fixture for VAL-007 (M7): Python SSRF sink fed by a tainted source.
#
# The tldr-core taint scanner needs:
#   - a source pattern from `get_sources(Language::Python)` — we use
#     `request.args` (Flask GET parameter) to taint variable `target`
#   - the tainted variable name appearing on the SAME line as the sink
#     pattern (the scanner does `line.contains(sink_pattern) && line.contains(var)`)
#   - a sink pattern from `get_sinks(VulnType::Ssrf, Language::Python)` —
#     post-fix this includes `requests.get(`, `requests.post(`,
#     `urllib.request.urlopen(`, `httpx.get(`
#
# On unfixed HEAD, `get_sinks(VulnType::Ssrf, Language::Python)` returns
# `vec![]`, so the line-scanning second pass in `scan_file_vulns` never
# matches — `findings` stays empty for this fixture.

from flask import request
import requests
import urllib.request
import httpx


def fetch_user_target():
    target = request.args.get("url")
    # sink: requests.get( with tainted `target`
    return requests.get(target)


def post_user_target():
    target = request.args.get("url")
    # sink: requests.post( with tainted `target`
    return requests.post(target, data={"a": 1})


def open_user_target():
    target = request.args.get("url")
    # sink: urllib.request.urlopen( with tainted `target`
    return urllib.request.urlopen(target)


def httpx_user_target():
    target = request.args.get("url")
    # sink: httpx.get( with tainted `target`
    return httpx.get(target)
