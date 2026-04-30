// vt=CommandInjection lang=typescript — names below are inside strings/comments only
// Documentation: req.query.id is a source. db.query(...) is a sink.
// child_process.exec, fs.readFileSync, fetch, eval, res.send are sinks.

export function docsOnly() {
    const doc: string = "req.query.id flows into db.query(SELECT ...) and child_process.exec";
    const more: string = "fetch(url) and fs.readFileSync(p) and eval(code) and res.send(html)";
    return doc + more;
}
