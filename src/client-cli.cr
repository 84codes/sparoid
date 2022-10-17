require "option_parser"
require "./client"
require "./version"

subcommand = :none
host = "0.0.0.0"
port = 8484
tcp_port = 22
config_path = "~/.sparoid.ini"

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
    p.on("-c PATH", "--config=PATH", "Path to config file") { |v| config_path = v }
  end
  p.on("connect", "Send a SPA, connect to a host/port and then pass the FD to parent") do
    subcommand = :connect
    p.banner = "Usage: #{PROGRAM_NAME} connect [arguments]"
    p.on("-h HOST", "--host=HOST", "Host to connect to") { |v| host = v }
    p.on("-p PORT", "--port=PORT", "UDP port") { |v| port = v.to_i }
    p.on("-P PORT", "--tcp-port=PORT", "TCP port") { |v| tcp_port = v.to_i }
    p.on("-c PATH", "--config=PATH", "Path to config file") { |v| config_path = v }
  end
end
parser.parse

begin
  case subcommand
  when :keygen
    Sparoid::Client.keygen
  when :send
    Sparoid::Client.new(config_path).send(host, port)
  when :connect
    ips = Sparoid::Client.new(config_path).send(host, port)
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
