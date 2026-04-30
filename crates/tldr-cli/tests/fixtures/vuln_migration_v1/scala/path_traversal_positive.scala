object Demo {
  def handler(request: play.api.mvc.RequestHeader, stmt: java.sql.Statement): Unit = {
    val p = request.getQueryString("p").get
    scala.io.Source.fromFile(p).mkString
  }
}
