#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handler(void *conn) {
    char *p = getenv("P");
    fopen(p, "r");
}
