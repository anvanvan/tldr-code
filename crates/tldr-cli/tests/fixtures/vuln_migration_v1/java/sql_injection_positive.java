import javax.servlet.http.*;
import java.sql.*;

public class Demo {
    public void handler(HttpServletRequest request, Statement stmt) throws Exception {
        String id = request.getParameter("id");
        stmt.executeQuery("SELECT * FROM u WHERE id = " + id);
    }
}
