// vt=CommandInjection lang=swift — names below are inside strings/comments only
// request.query[...] is a source. executeQuery, Process.launchedProcess,
// FileHandle are sinks — referenced in strings only here.

import Foundation

func docs() -> String {
    let doc = "request.query[id] flows into stmt.executeQuery(SELECT ... )"
    let more = "Process.launchedProcess, FileHandle(forReadingAtPath:) — string-only"
    return doc + more
}
