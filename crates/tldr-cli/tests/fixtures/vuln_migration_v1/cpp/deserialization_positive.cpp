#include <cstdlib>
#include <cstdio>
#include <string>

void handler(void *conn) {
    std::string d = std::getenv("D");
    boost::archive::text_iarchive ia(std::stringstream(d) >> obj);
}
