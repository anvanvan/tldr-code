// vt=PathTraversal lang=kotlin — names below are inside strings/comments only
// call.request.queryParameters[...] is a source.
// stmt.executeQuery, Runtime.getRuntime().exec, java.io.File, ObjectInputStream are sinks.

fun docs(): String {
    val doc = "call.request.queryParameters flows into stmt.executeQuery(SELECT ... )"
    val more = "Runtime.getRuntime().exec, java.io.File, ObjectInputStream — string-only"
    return doc + more
}
