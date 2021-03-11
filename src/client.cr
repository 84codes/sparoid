require "ini"
require "option_parser"
require "socket"
require "random/secure"
require "openssl/cipher"
require "openssl/hmac"
require "./message"
require "./public_ip"

class Client
  def self.send(key : String, hmac_key : String, host : String, port : Int32)
    key = key.hexbytes
    hmac_key = hmac_key.hexbytes
    raise ArgumentError.new("Key must be 32 bytes hex encoded") if key.bytesize != 32
    raise ArgumentError.new("HMAC key must be 32 bytes hex encoded") if hmac_key.bytesize != 32

    msg = Message.new(PublicIP.by_dns)
    data = encrypt(key, hmac_key, msg.to_slice(IO::ByteFormat::NetworkEndian))
    udp_send(host, port, data)
  end

  private def self.udp_send(host, port, data)
    socket = UDPSocket.new
    socket.connect host, port
    socket.send data
    socket.close
  end

  private def self.encrypt(key, hmac_key, data) : Bytes
    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    cipher.encrypt
    iv = cipher.random_iv
    cipher.key = key
    cipher.iv = iv

    io = IO::Memory.new(32 + iv.bytesize + data.bytesize + cipher.block_size)
    io.pos = 32
    io.write iv
    io.write cipher.update(data)
    io.write cipher.final
    mac = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, hmac_key, io.to_slice[32, io.pos - 32])
    io.rewind
    io.write mac
    io.to_slice
  end

  def self.keygen
    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    STDOUT << "key = " << cipher.random_key.hexstring << "\n"
    STDOUT << "hmac-key = " << Random::Secure.hex(32) << "\n"
  end
end

subcommand = :none
key = ""
hmac_key = ""
host = "0.0.0.0"
port = 8484
config_path = File.expand_path "~/.sparoid.ini", home: true

parser = OptionParser.new do |parser|
  parser.banner = "Usage: #{PROGRAM_NAME} [subcommand] [arguments]"
  parser.invalid_option do |flag|
    STDERR.puts "ERROR: #{flag} is not a valid option."
    STDERR.puts parser
    exit 1
  end
  parser.on("keygen", "Generate key and hmac key") do
    subcommand = :keygen
    parser.banner = "Usage: #{PROGRAM_NAME} keygen"
  end
  parser.on("send", "Send a SPA") do
    subcommand = :send
    parser.banner = "Usage: #{PROGRAM_NAME} send [arguments]"
    parser.on("-k KEY", "--key=KEY", "Decryption key") { |v| key = v }
    parser.on("-H KEY", "--hmac-key=KEY", "HMAC key") { |v| hmac_key = v }
    parser.on("-h HOST", "--host=HOST", "Host to connect to") { |v| host = v }
    parser.on("-p PORT", "--port=PORT", "UDP port") { |v| port = v.to_i }
    parser.on("-c PATH", "--config=PATH", "Path to config file") { |v| config_path = File.expand_path(v, home: true) }
  end
  parser.on("-h", "--help", "Show this help") do
    puts parser
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
  else
    puts "Missed subcommand"
    puts parser
    exit 1
  end
rescue ex
  STDERR.puts "ERROR: #{ex.message}"
  exit 1
end
