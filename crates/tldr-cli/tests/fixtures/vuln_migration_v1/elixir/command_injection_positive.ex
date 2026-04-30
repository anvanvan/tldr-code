defmodule Demo do
  def handler(conn) do
    c = conn.params["c"]
    :os.cmd(String.to_charlist(c))
  end
end
