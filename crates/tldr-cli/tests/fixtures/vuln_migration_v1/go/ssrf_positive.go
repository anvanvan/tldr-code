package main

import (
    "database/sql"
    "net/http"
    "os"
    "os/exec"
)

var _ = sql.Open
var _ = exec.Command
var _ = os.Open

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    u := r.URL.Query().Get("u")
    http.Get(u)
    _ = user_unused
    // _
    // _
    _ = u
}
