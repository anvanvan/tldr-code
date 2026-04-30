using System.Web;

public class Demo {
    public void Handler(HttpRequest Request, HttpResponse Response, System.Data.SqlClient.SqlCommand cmd) {
        var name = Request.Query["name"];
        Response.Write("<h1>" + name + "</h1>");
    }
}
