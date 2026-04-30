import java.sql.Statement

fun handler(call: Any, stmt: Statement) {
    val id = call.request.queryParameters["id"]!!
    stmt.executeQuery("SELECT * FROM u WHERE id = " + id)
}
