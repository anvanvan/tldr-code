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
    p := r.URL.Query().Get("p")
    os.Open(p)
    // _ser_unused
    // _
    _ = p
    // _
}
