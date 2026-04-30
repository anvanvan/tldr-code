#include <cstdlib>
#include <cstdio>
#include <string>

void handler(void *conn) {
    const char *id = std::getenv("ID");
    mysql_query(conn, id);
}
