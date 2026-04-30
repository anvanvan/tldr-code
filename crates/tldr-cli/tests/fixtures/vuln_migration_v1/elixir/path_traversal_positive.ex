defmodule Demo do
  def handler(conn) do
    p = conn.params["p"]
    File.read!(p)
  end
end
