// vt=CommandInjection lang=csharp — names below are inside strings/comments only
// Request.Query[...] is a source. cmd.ExecuteReader, Response.Write,
// System.Diagnostics.Process.Start, System.IO.File.Open, JavaScriptSerializer are sinks.

public class DocsOnly {
    public string Docs() {
        string doc = "Request.Query[id] flows into cmd.ExecuteReader(SELECT ... )";
        string more = "Response.Write, Process.Start, System.IO.File.Open, JavaScriptSerializer";
        return doc + more;
    }
}
