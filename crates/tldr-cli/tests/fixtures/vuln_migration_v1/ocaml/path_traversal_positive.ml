let handler stmt =
  let p = Sys.getenv "P" in
  ignore (open_in p)
