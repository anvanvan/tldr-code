require 'yaml'
require 'net/http'

class DemoController
  def handler(params)
    name = params[:name]
    render html: ("<h1>" + name + "</h1>").html_safe
  end
end
