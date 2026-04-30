defmodule Demo do
  def handler(conn) do
    d = conn.params["d"]
    :erlang.binary_to_term(d)
  end
end
