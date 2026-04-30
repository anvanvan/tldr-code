package main

// VULN-MIGRATION-V1 M1: Composite multi-pattern string-literal regression fixture.
//
// This file references ALL 6 source-pattern strings for Go (r.URL.Query, r.FormValue,
// r.PostFormValue, r.Header.Get, os.Args, os.Getenv) and ALL representative
// Go sink-pattern strings (db.Query, exec.Command, os.Open, http.Get, ioutil.ReadFile)
// EXCLUSIVELY inside string literals or comments. Asserts ZERO findings —
// the closes-#24 root pattern at the file scale.
//
// Comment-only patterns:
//   r.URL.Query().Get("id")
//   r.FormValue("x")
//   r.PostFormValue("y")
//   r.Header.Get("X-Token")
//   os.Args[1]
//   os.Getenv("CMD")
//   db.Query("SELECT * FROM u")
//   exec.Command("sh", "-c", "ls")
//   os.Open("/etc/passwd")
//   http.Get("http://attacker")
//   ioutil.ReadFile("/secret")

func DocsOnly() (string, string, string) {
    sources := "r.URL.Query | r.FormValue | r.PostFormValue | r.Header.Get | os.Args | os.Getenv"
    sinks := "db.Query | exec.Command | os.Open | http.Get | ioutil.ReadFile"
    both := "Source r.URL.Query().Get(\"id\") flows into sink db.Query(\"SELECT ... \")"
    return sources, sinks, both
}
