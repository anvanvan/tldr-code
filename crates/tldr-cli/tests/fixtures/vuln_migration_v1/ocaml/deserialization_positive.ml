let handler stmt =
  let d = Sys.getenv "D" in
  ignore (Marshal.from_string d 0)
