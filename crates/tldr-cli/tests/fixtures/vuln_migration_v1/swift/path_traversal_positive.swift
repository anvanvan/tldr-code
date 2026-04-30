import Foundation

func handler(request: Any, stmt: Any) throws {
    let p = request.query["p"]!
    FileHandle(forReadingAtPath: p)
}
