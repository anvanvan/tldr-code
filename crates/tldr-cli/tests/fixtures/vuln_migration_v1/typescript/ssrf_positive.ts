export function handler(req: any, res: any, db: any) {
    const u = req.query.u;
    fetch(u);
}
