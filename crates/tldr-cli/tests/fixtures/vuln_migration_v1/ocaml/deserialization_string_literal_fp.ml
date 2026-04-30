(* vt=Deserialization lang=ocaml — names below are inside strings/comments only
 *
 * Sys.getenv is a source. Mariadb.Stmt.execute, Sys.command,
 * open_in, Marshal.from_string are sinks. String-only references below.
 *)

let docs () =
  let doc = "Sys.getenv flows into Mariadb.Stmt.execute(SELECT ... )" in
  let more = "Sys.command, open_in, Marshal.from_string — string-only references" in
  doc ^ more
