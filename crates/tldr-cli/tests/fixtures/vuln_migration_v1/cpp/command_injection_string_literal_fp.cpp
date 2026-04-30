// vt=CommandInjection lang=cpp — names below are inside strings/comments only
// std::getenv, mysql_query, std::system, std::fopen, boost::archive::text_iarchive
// are referenced in strings only below.

#include <string>
std::string docs() {
    std::string s = "std::getenv -> mysql_query, std::system, std::fopen, boost::archive::text_iarchive";
    return s;
}
