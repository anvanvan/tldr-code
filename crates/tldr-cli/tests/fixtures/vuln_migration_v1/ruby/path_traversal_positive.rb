require 'yaml'
require 'net/http'

class DemoController
  def handler(params)
    p = params[:p]
    File.open(p).read
  end
end
