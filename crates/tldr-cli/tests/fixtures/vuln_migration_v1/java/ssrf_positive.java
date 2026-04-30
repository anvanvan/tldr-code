import javax.servlet.http.*;
import java.sql.*;

public class Demo {
    public void handler(HttpServletRequest request, Statement stmt) throws Exception {
        String u = request.getParameter("u");
        new java.net.URL(u).openConnection();
    }
}
