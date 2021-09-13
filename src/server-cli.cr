require "./server"
require "./config"

begin
  c = Sparoid::Config.new
  puts "Listening: #{c.host}:#{c.port}"
  puts "Open command: #{c.open_cmd}"
  puts "Close command: #{c.close_cmd}"
  puts "Keys: #{c.keys.size}"
  puts "HMAC keys: #{c.hmac_keys.size}"
  s = Sparoid::Server.new(c.keys, c.hmac_keys, c.open_cmd, c.close_cmd)
  s.bind(c.host, c.port)
  s.listen
rescue ex
  STDERR.puts "ERROR: #{ex.message}"
  exit 1
end
