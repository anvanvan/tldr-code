import Foundation

func handler(request: Any, stmt: Any) throws {
    let id = request.query["id"]!
    try stmt.executeQuery("SELECT * FROM u WHERE id = " + id)
}
