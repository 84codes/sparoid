require "./server"
require "./config"

begin
  c = Sparoid::Config.new
  puts "Listening: #{c.host}:#{c.port}"
  puts "Open command: #{c.open_cmd}"
  puts "Close command: #{c.close_cmd}"
  s = Sparoid::Server.new(c.key, c.hmac_key, c.open_cmd, c.close_cmd)
  s.bind(c.host, c.port)
  s.listen
rescue ex
  STDERR.puts "ERROR: #{ex.message}"
  exit 1
end
