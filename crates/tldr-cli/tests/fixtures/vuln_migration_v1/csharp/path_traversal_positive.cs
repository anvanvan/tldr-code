using System.Web;

public class Demo {
    public void Handler(HttpRequest Request, HttpResponse Response, System.Data.SqlClient.SqlCommand cmd) {
        var p = Request.Query["p"];
        System.IO.File.Open(p, System.IO.FileMode.Open);
    }
}
