# vt=SqlInjection lang=elixir — names below are inside strings/comments only
# conn.params is a source. Ecto SQL.query, Phoenix.HTML.raw,
# :os.cmd, File.read!, :erlang.binary_to_term are sinks. String-only refs below.

defmodule DocsOnly do
  def docs do
    doc = "conn.params[id] flows into Ecto.Adapters.SQL.query!(SELECT ... )"
    more = "Phoenix.HTML.raw, :os.cmd, File.read!, :erlang.binary_to_term"
    doc <> more
  end
end
