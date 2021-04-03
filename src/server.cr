require "./sparoid/server"
require "./sparoid/config"

begin
  c = Config.new
  puts "Listening: #{c.host}:#{c.port}"
  puts "Open command: #{c.open_cmd}"
  puts "Close command: #{c.close_cmd}"
  Server.new(c.key, c.hmac_key, c.open_cmd, c.close_cmd).listen(c.host, c.port)
rescue ex
  STDERR.puts "ERROR: #{ex.message}"
  exit 1
end
