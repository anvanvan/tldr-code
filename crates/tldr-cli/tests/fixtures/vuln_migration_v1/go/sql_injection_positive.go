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
    user := r.URL.Query().Get("id")
    db.Query("SELECT * FROM u WHERE id = " + user)
    // _ser
    // _
    // _
    // _
}
