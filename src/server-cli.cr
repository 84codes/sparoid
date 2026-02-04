require "socket"
require "./server"
require "./config"
require "./nftables"

begin
  c = Sparoid::Config.new
  puts "Listening: #{c.host}:#{c.port}"
  puts "Keys: #{c.keys.size}"
  puts "HMAC keys: #{c.hmac_keys.size}"
  if c.nftables_cmd.bytesize > 0
    puts "nftables command: #{c.nftables_cmd}"
    nft = Nftables.new
    on_accept = ->(ip_str : String) {
      nft.run_cmd sprintf(c.nftables_cmd, ip_str)
    }
  else
    puts "Open command: #{c.open_cmd}"
    puts "Close command: #{c.close_cmd}"
    on_accept = ->(ip_str : String) : Nil {
      spawn do
        system sprintf(c.open_cmd, ip_str)
        unless c.close_cmd.empty?
          sleep 15.seconds
          system sprintf(c.close_cmd, ip_str)
        end
      end
    }
  end
  address = Socket::IPAddress.new(c.host, c.port)
  s = Sparoid::Server.new(c.keys, c.hmac_keys, on_accept, address)
  s.bind
  s.listen
rescue ex
  STDERR.puts "ERROR: #{ex.message}"
  exit 1
end
