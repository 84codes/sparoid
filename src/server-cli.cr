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

module Firewall
  # created when the first profile with a nftables command is loaded
  class_getter nft : Nftables { Nftables.new }
end

def print_config(c : Sparoid::Config) : Nil
  c.warnings.each { |warning| STDERR.puts "WARNING: #{warning}" }
  c.profiles.each do |profile|
    puts "Profile: #{profile}"
    puts "  Keys: #{profile.keys.size}"
    puts "  HMAC keys: #{profile.hmac_keys.size}"
    if profile.nftables?
      puts "  nftables command: #{profile.nftables_cmd}"
      puts "  nftablesv6 command: #{profile.nftablesv6_cmd}"
    else
      puts "  Open command: #{profile.open_cmd}"
      puts "  Close command: #{profile.close_cmd}"
    end
  end
end

def server_profiles(c : Sparoid::Config) : Array(Sparoid::Server::Profile)
  c.profiles.map do |profile|
    action = on_accept(profile, profile.nftables? ? Firewall.nft : nil)
    Sparoid::Server::Profile.new(profile.name, profile.keys, profile.hmac_keys, action)
  end
end

# Reload the config file, the server keeps running with
# its current config if the file is invalid
def reload(server : Sparoid::Server, current : Sparoid::Config) : Nil
  c = Sparoid::Config.load(current.config_file)
  server.profiles = server_profiles(c)
  print_config(c)
  if c.host != current.host || c.port != current.port
    STDERR.puts "WARNING: bind/port can't be changed by a reload, still listening on #{current.host}:#{current.port}, restart to apply"
  end
  puts "Config reloaded"
rescue ex
  STDERR.puts "ERROR: Config reload failed, keeping the current config: #{ex.message}"
end

begin
  c = Sparoid::Config.new
  puts "Listening: #{c.host}:#{c.port}"
  print_config(c)
  if c.check?
    puts "Config file '#{c.config_file}' is valid"
    exit
  end
  address = Socket::IPAddress.new(c.host, c.port)
  s = Sparoid::Server.new(server_profiles(c), address)
  s.bind
  # Process.on_terminate would also take over SIGINT and SIGTERM
  Signal::HUP.trap { reload(s, c) } # ameba:disable Lint/SignalTrap
  s.listen
rescue ex
  STDERR.puts "ERROR: #{ex.message}"
  exit 1
end
