export function handler(req, res, db) {
    const p = req.query.p;
    fs.readFileSync(p, "utf8");
}
