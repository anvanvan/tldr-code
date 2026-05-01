// js-res-json-fp-narrowing-v1 FP regression-guard fixture.
//
// `res.json(tainted)` writes a JSON HTTP response — there is no file
// open, no path involved. Pre-fix, the FileWrite/PathTraversal sink
// bank had ("res", "json"), ("response", "json"), ("Response", "json"),
// ("NextResponse", "json") which (via vuln_type_from_sink: FileWrite ->
// PathTraversal) emitted spurious path_traversal findings.
//
// Empirical repro (Express):
//   /tmp/repos/express/test/express.raw.js:506
//     res.json({ buf: req.body.toString('hex') })
//
// Post-fix: ZERO path_traversal findings on this file.
export function handler(req, res) {
    res.json(req.body);
    res.json({ name: req.query.name });
    response.json(req.body);
    Response.json(req.body);
    NextResponse.json({ data: req.query.id });
}
