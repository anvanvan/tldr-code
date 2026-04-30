let handler stmt =
  let id = Sys.getenv "ID" in
  ignore (Mariadb.Stmt.execute stmt ("SELECT * FROM u WHERE id = " ^ id))
