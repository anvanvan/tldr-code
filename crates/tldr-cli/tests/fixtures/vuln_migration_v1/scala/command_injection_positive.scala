object Demo {
  def handler(request: play.api.mvc.RequestHeader, stmt: java.sql.Statement): Unit = {
    val c = request.getQueryString("c").get
    Runtime.getRuntime.exec(c)
  }
}
