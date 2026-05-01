// js-res-json-fp-narrowing-v1 FP regression-guard fixture (TypeScript parity).
// See path_traversal_res_json_fp.js for the rationale.
export function handler(req: any, res: any) {
    res.json(req.body);
    res.json({ name: req.query.name });
    response.json(req.body);
    Response.json(req.body);
    NextResponse.json({ data: req.query.id });
}
