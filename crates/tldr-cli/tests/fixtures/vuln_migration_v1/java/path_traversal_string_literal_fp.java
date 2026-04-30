// vt=PathTraversal lang=java — names below are inside strings/comments only
// request.getParameter is a source; stmt.executeQuery, Runtime.getRuntime().exec,
// new java.io.File, new java.net.URL, new java.io.ObjectInputStream are sinks.

public class DocsOnly {
    public String docs() {
        String doc = "request.getParameter -> stmt.executeQuery(SELECT ... )";
        String more = "Runtime.getRuntime().exec, new java.io.File, new java.net.URL, ObjectInputStream";
        return doc + more;
    }
}
