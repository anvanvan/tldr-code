import java.sql.Statement

fun handler(call: Any, stmt: Statement) {
    val d = call.request.queryParameters["d"]!!
    java.io.ObjectInputStream(java.io.ByteArrayInputStream(d.toByteArray())).readObject()
}
