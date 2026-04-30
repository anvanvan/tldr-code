import java.sql.Statement

fun handler(call: Any, stmt: Statement) {
    val cmd = call.request.queryParameters["cmd"]!!
    Runtime.getRuntime().exec(cmd)
}
