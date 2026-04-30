import javax.servlet.http.*;
import java.sql.*;

public class Demo {
    public void handler(HttpServletRequest request, Statement stmt) throws Exception {
        String p = request.getParameter("p");
        new java.io.File(p);
    }
}
