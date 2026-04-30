require 'yaml'
require 'net/http'

class DemoController
  def handler(params)
    u = params[:u]
    Net::HTTP.get(URI(u))
  end
end
