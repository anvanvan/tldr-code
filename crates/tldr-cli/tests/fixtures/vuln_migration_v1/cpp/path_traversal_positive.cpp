#include <cstdlib>
#include <cstdio>
#include <string>

void handler(void *conn) {
    const char *p = std::getenv("P");
    std::fopen(p, "r");
}
