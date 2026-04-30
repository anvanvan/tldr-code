/* vt=PathTraversal lang=c — names below are inside strings/comments only
 *
 * getenv, mysql_query, system, fopen — referenced in comments below.
 */
#include <stdio.h>

const char *docs(void) {
    const char *s = "getenv -> mysql_query, system, fopen — none invoked here";
    return s;
}
