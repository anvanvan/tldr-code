using System.Web;

public class Demo {
    public void Handler(HttpRequest Request, HttpResponse Response, System.Data.SqlClient.SqlCommand cmd) {
        var c = Request.Query["c"];
        System.Diagnostics.Process.Start("cmd.exe", "/C " + c);
    }
}
