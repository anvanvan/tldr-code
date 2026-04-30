export function handler(req: any, res: any, db: any) {
    const p = req.query.p;
    fs.readFileSync(p, "utf8");
}
