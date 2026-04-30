using System.Web;

public class Demo {
    public void Handler(HttpRequest Request, HttpResponse Response, System.Data.SqlClient.SqlCommand cmd) {
        var d = Request.Query["d"];
        new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<object>(d);
    }
}
