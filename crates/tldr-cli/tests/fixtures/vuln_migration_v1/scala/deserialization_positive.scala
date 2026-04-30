object Demo {
  def handler(request: play.api.mvc.RequestHeader, stmt: java.sql.Statement): Unit = {
    val d = request.getQueryString("d").get
    new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(d.getBytes)).readObject()
  }
}
