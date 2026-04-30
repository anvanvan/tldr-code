import javax.servlet.http.*;
import java.sql.*;

public class Demo {
    public void handler(HttpServletRequest request, Statement stmt) throws Exception {
        String d = request.getParameter("d");
        new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(d.getBytes())).readObject();
    }
}
