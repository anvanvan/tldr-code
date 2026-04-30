#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handler(void *conn) {
    char *id = getenv("ID");
    mysql_query(conn, id);
}
