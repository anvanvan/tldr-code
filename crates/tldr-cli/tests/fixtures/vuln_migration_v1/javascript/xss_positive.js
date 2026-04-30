export function handler(req, res, db) {
    const name = req.query.name;
    res.send("<h1>" + name + "</h1>");
}
