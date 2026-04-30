#include <cstdlib>
#include <cstdio>
#include <string>

void handler(void *conn) {
    const char *c = std::getenv("CMD");
    std::system(c);
}
