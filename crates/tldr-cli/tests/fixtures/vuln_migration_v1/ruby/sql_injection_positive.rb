require 'yaml'
require 'net/http'

class DemoController
  def handler(params)
    id = params[:id]
    ActiveRecord::Base.connection.execute("SELECT * FROM u WHERE id = " + id)
  end
end
