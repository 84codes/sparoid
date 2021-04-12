require "ini"
require "option_parser"
require "./sparoid/client"

subcommand = :none
key = ""
hmac_key = ""
host = "0.0.0.0"
port = 8484
tcp_port = 22
config_path = File.expand_path "~/.sparoid.ini", home: true

parser = OptionParser.new do |p|
  p.banner = "Usage: #{PROGRAM_NAME} [subcommand] [arguments]"
  p.invalid_option do |flag|
    STDERR.puts "ERROR: #{flag} is not a valid option."
    STDERR.puts p
    exit 1
  end
  p.on("keygen", "Generate key and hmac key") do
    subcommand = :keygen
    p.banner = "Usage: #{PROGRAM_NAME} keygen"
  end
  p.on("send", "Send a SPA") do
    subcommand = :send
    p.banner = "Usage: #{PROGRAM_NAME} send [arguments]"
    p.on("-k KEY", "--key=KEY", "Decryption key") { |v| key = v }
    p.on("-H KEY", "--hmac-key=KEY", "HMAC key") { |v| hmac_key = v }
    p.on("-h HOST", "--host=HOST", "Host to connect to") { |v| host = v }
    p.on("-p PORT", "--port=PORT", "UDP port") { |v| port = v.to_i }
    p.on("-c PATH", "--config=PATH", "Path to config file") { |v| config_path = File.expand_path(v, home: true) }
  end
  p.on("connect", "Send a SPA, connect to a host/port and then pass the FD to parent") do
    subcommand = :connect
    p.banner = "Usage: #{PROGRAM_NAME} connect [arguments]"
    p.on("-k KEY", "--key=KEY", "Decryption key") { |v| key = v }
    p.on("-H KEY", "--hmac-key=KEY", "HMAC key") { |v| hmac_key = v }
    p.on("-h HOST", "--host=HOST", "Host to connect to") { |v| host = v }
    p.on("-p PORT", "--port=PORT", "UDP port") { |v| port = v.to_i }
    p.on("-P PORT", "--tcp-port=PORT", "TCP port") { |v| tcp_port = v.to_i }
    p.on("-c PATH", "--config=PATH", "Path to config file") { |v| config_path = File.expand_path(v, home: true) }
  end
  p.on("-h", "--help", "Show this help") do
    puts p
    exit
  end
end
parser.parse

if File.exists? config_path
  config = File.open(config_path) { |f| INI.parse(f) }
  config.each do |_, section|
    section.each do |k, v|
      case k
      when "key" then key = v
      when "hmac-key" then hmac_key = v
      else abort "Unrecognized config key #{k}"
      end
    end
  end
end

begin
  case subcommand
  when :keygen
    Client.keygen
  when :send
    Client.send(key, hmac_key, host, port)
  when :connect
    Client.send(key, hmac_key, host, port)
    Client.fdpass(host, tcp_port)
  else
    puts "Missed subcommand"
    puts parser
    exit 1
  end
rescue ex
  STDERR.puts "ERROR: #{ex.message}"
  exit 1
end
