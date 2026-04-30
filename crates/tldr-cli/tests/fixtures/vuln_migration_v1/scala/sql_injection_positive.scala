object Demo {
  def handler(request: play.api.mvc.RequestHeader, stmt: java.sql.Statement): Unit = {
    val id = request.getQueryString("id").get
    stmt.executeQuery("SELECT * FROM u WHERE id = " + id)
  }
}
