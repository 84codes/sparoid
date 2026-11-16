require "socket"
require "./server"
require "./config"
require "./nftables"

# Build the action that opens the firewall for a profile
def on_accept(profile : Sparoid::Config::Profile, nft : Nftables?) : Sparoid::Server::AcceptProc
  if nft
    nftables_cmd = profile.nftables_cmd
    nftablesv6_cmd = profile.nftablesv6_cmd
    ->(ip_str : String, family : Socket::Family) : Nil {
      case family
      when Socket::Family::INET6
        if nftablesv6_cmd.bytesize > 0
          nft.run_cmd sprintf(nftablesv6_cmd, ip_str)
        else
          puts "WARNING: no nftablesv6-cmd configured for profile '#{profile}', skipping #{ip_str}"
        end
      when Socket::Family::INET
        if nftables_cmd.bytesize > 0
          nft.run_cmd sprintf(nftables_cmd, ip_str)
        else
          puts "WARNING: no nftables-cmd configured for profile '#{profile}', skipping #{ip_str}"
        end
      end
    }
  else
    open_cmd = profile.open_cmd
    close_cmd = profile.close_cmd
    ->(ip_str : String, _family : Socket::Family) : Nil {
      spawn do
        system sprintf(open_cmd, ip_str)
        unless close_cmd.empty?
          sleep 15.seconds
          system sprintf(close_cmd, ip_str)
        end
      end
    }
  end
end

begin
  c = Sparoid::Config.new
  puts "Listening: #{c.host}:#{c.port}"
  nft = nil
  profiles = c.profiles.map do |profile|
    puts "Profile: #{profile}"
    puts "  Keys: #{profile.keys.size}"
    puts "  HMAC keys: #{profile.hmac_keys.size}"
    if profile.nftables?
      puts "  nftables command: #{profile.nftables_cmd}"
      puts "  nftablesv6 command: #{profile.nftablesv6_cmd}"
      nft ||= Nftables.new
      action = on_accept(profile, nft)
    else
      puts "  Open command: #{profile.open_cmd}"
      puts "  Close command: #{profile.close_cmd}"
      action = on_accept(profile, nil)
    end
    Sparoid::Server::Profile.new(profile.name, profile.keys, profile.hmac_keys, action)
  end
  address = Socket::IPAddress.new(c.host, c.port)
  s = Sparoid::Server.new(profiles, address)
  s.bind
  s.listen
rescue ex
  STDERR.puts "ERROR: #{ex.message}"
  exit 1
end
