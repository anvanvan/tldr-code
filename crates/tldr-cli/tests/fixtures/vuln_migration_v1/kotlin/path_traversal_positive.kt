import java.sql.Statement

fun handler(call: Any, stmt: Statement) {
    val p = call.request.queryParameters["p"]!!
    java.io.File(p).readText()
}
