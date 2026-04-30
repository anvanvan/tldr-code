package main

// vt=Ssrf lang=go — names below are inside strings/comments only
//
// The following call patterns are described here in COMMENTS only and
// never appear as real expressions:
//   r.URL.Query().Get("id")
//   db.Query("SELECT ... ")
//   exec.Command("sh", "-c", cmd).Run()
//   os.Open(p)
//   http.Get(u)

func DocsOnly() string {
    doc := "r.URL.Query().Get returns a source. db.Query is a sink. exec.Command runs commands."
    more := "os.Open opens a path. http.Get fetches a URL. None of these are invoked here."
    return doc + more
}
