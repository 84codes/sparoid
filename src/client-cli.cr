require "ini"
require "option_parser"
require "./client"
require "./version"

subcommand = :none
key = ENV.fetch("SPAROID_KEY", "")
hmac_key = ENV.fetch("SPAROID_HMAC_KEY", "")
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
  p.on("--help", "Show this help") do
    puts p
    exit
  end
  p.on("--version", "Show version") do
    puts Sparoid::VERSION
    exit
  end
  p.on("keygen", "Generate key and hmac key") do
    subcommand = :keygen
    p.banner = "Usage: #{PROGRAM_NAME} keygen"
  end
  p.on("send", "Send a SPA") do
    subcommand = :send
    p.banner = "Usage: #{PROGRAM_NAME} send [arguments]"
    p.on("-h HOST", "--host=HOST", "Host to connect to") { |v| host = v }
    p.on("-p PORT", "--port=PORT", "UDP port") { |v| port = v.to_i }
    p.on("-c PATH", "--config=PATH", "Path to config file") { |v| config_path = File.expand_path(v, home: true) }
  end
  p.on("connect", "Send a SPA, connect to a host/port and then pass the FD to parent") do
    subcommand = :connect
    p.banner = "Usage: #{PROGRAM_NAME} connect [arguments]"
    p.on("-h HOST", "--host=HOST", "Host to connect to") { |v| host = v }
    p.on("-p PORT", "--port=PORT", "UDP port") { |v| port = v.to_i }
    p.on("-P PORT", "--tcp-port=PORT", "TCP port") { |v| tcp_port = v.to_i }
    p.on("-c PATH", "--config=PATH", "Path to config file") { |v| config_path = File.expand_path(v, home: true) }
  end
end
parser.parse

if File.exists? config_path
  config = File.open(config_path) { |f| INI.parse(f) }
  config.each do |_, section|
    section.each do |k, v|
      case k
      when "key"      then key = v
      when "hmac-key" then hmac_key = v
      end
    end
  end
end

begin
  case subcommand
  when :keygen
    Sparoid::Client.keygen
  when :send
    Sparoid::Client.send(key, hmac_key, host, port)
  when :connect
    ips = Sparoid::Client.send(key, hmac_key, host, port)
    Sparoid::Client.fdpass(ips, tcp_port)
  else
    puts "Missed subcommand"
    puts parser
    exit 1
  end
rescue ex
  STDERR.puts "Sparoid error: #{ex.message}"
  exit 1
end
