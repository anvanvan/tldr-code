export function handler(req, res, db) {
    const id = req.query.id;
    db.query("SELECT * FROM u WHERE id = " + id);
}
