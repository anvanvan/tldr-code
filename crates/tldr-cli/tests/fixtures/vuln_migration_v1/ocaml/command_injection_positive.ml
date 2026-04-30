let handler stmt =
  let c = Sys.getenv "CMD" in
  ignore (Sys.command c)
