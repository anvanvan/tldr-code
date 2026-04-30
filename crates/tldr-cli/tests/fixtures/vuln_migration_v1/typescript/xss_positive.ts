export function handler(req: any, res: any, db: any) {
    const name = req.query.name;
    res.send("<h1>" + name + "</h1>");
}
