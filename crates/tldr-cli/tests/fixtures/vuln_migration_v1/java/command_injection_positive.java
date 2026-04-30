import javax.servlet.http.*;
import java.sql.*;

public class Demo {
    public void handler(HttpServletRequest request, Statement stmt) throws Exception {
        String c = request.getParameter("c");
        Runtime.getRuntime().exec(c);
    }
}
