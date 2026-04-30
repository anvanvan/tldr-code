export function handler(req: any, res: any, db: any) {
    const cmd = req.query.cmd;
    child_process.exec(cmd);
}
