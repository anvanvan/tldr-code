# vt=Xss lang=ruby — names below are inside strings/comments only
# params[:id] is a source. ActiveRecord execute, render html_safe,
# `cmd`, File.open, Net::HTTP.get, YAML.load are sinks.

class DocsOnly
  def docs
    doc = "params[:id] flows into ActiveRecord::Base.connection.execute(SELECT ...)"
    more = "render html_safe; backtick cmd; File.open(p); Net::HTTP.get(u); YAML.load(d)"
    "#{doc} #{more}"
  end
end
