// vt=PathTraversal lang=scala — names below are inside strings/comments only
// request.getQueryString is a source. stmt.executeQuery, Runtime.getRuntime.exec,
// scala.io.Source.fromFile, ObjectInputStream are sinks — string-only references here.

object DocsOnly {
  def docs(): String = {
    val doc = "request.getQueryString flows into stmt.executeQuery(SELECT ... )"
    val more = "Runtime.getRuntime.exec, scala.io.Source.fromFile, ObjectInputStream"
    doc + more
  }
}
