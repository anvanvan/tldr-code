require 'yaml'
require 'net/http'

class DemoController
  def handler(params)
    d = params[:d]
    YAML.load(d)
  end
end
