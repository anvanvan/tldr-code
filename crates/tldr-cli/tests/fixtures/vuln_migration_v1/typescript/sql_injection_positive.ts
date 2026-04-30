export function handler(req: any, res: any, db: any) {
    const id = req.query.id;
    db.query("SELECT * FROM u WHERE id = " + id);
}
