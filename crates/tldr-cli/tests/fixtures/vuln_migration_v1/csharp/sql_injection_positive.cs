using System.Web;

public class Demo {
    public void Handler(HttpRequest Request, HttpResponse Response, System.Data.SqlClient.SqlCommand cmd) {
        var id = Request.Query["id"];
        cmd.ExecuteReader("SELECT * FROM u WHERE id = " + id);
    }
}
