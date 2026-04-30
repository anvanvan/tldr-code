defmodule Demo do
  def handler(conn) do
    id = conn.params["id"]
    Ecto.Adapters.SQL.query!(Repo, "SELECT * FROM u WHERE id = " <> id)
  end
end
