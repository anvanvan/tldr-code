require 'yaml'
require 'net/http'

class DemoController
  def handler(params)
    cmd = params[:cmd]
    `#{cmd}`
  end
end
