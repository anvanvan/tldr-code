defmodule Demo do
  def handler(conn) do
    name = conn.params["name"]
    Phoenix.HTML.raw("<h1>" <> name <> "</h1>")
  end
end
