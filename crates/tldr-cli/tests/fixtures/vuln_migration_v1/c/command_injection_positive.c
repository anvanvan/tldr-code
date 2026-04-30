#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handler(void *conn) {
    char *cmd = getenv("CMD");
    system(cmd);
}
