require "./server"
require "./config"
require "./nftables"

begin
  c = Sparoid::Config.new
  puts "Listening: #{c.hosts.join(", ")}:#{c.port}"
  puts "Keys: #{c.keys.size}"
  puts "HMAC keys: #{c.hmac_keys.size}"
  if c.nftables_cmd.bytesize > 0
    puts "nftables command: #{c.nftables_cmd}"
    nft = Nftables.new
    on_accept = ->(ip_str : String, family : Socket::Family) : Nil {
      case family
      when Socket::Family::INET6
        if c.nftablesv6_cmd.bytesize > 0
          puts "Running nftablesv6 command for #{ip_str}"
          nft.run_cmd sprintf(c.nftablesv6_cmd, ip_str)
        else
          puts "WARNING: no nftablesv6-cmd configured, skipping #{ip_str}"
        end
      when Socket::Family::INET
        puts "Running nftables command for #{ip_str}"
        nft.run_cmd sprintf(c.nftables_cmd, ip_str)
      end
    }
  else
    puts "Open command: #{c.open_cmd}"
    puts "Close command: #{c.close_cmd}"
    on_accept = ->(ip_str : String, _family : Socket::Family) : Nil {
      spawn do
        system sprintf(c.open_cmd, ip_str)
        unless c.close_cmd.empty?
          sleep 15.seconds
          system sprintf(c.close_cmd, ip_str)
        end
      end
    }
  end

  servers = c.hosts.map do |host|
    address = Socket::IPAddress.new(host, c.port)
    s = Sparoid::Server.new(c.keys, c.hmac_keys, on_accept, address.family)
    s.bind(address)
    s
  end

  servers.each do |s| # ameba:disable Naming/BlockParameterName
    spawn s.listen
  end

  sleep
rescue ex
  STDERR.puts "ERROR: #{ex.message}"
  exit 1
end
