require "option_parser"
require "socket"
require "openssl/cipher"
require "openssl/hmac"
require "./message"

class Server
  @key : Bytes
  @hmac_key : Bytes

  def initialize(key, hmac_key, @open_cmd : String, @close_cmd : String)
    @key = key.hexbytes
    @hmac_key = hmac_key.hexbytes
    raise ArgumentError.new("Key must be 32 bytes hex encoded") if @key.bytesize != 32
    raise ArgumentError.new("HMAC key must be 32 bytes hex encoded") if @hmac_key.bytesize != 32
  end

  def listen(host = "0.0.0.0", port = 62201)
    socket = UDPSocket.new
    socket.bind host, port
    buffer = Bytes.new(512)
    loop do
      count, client_addr = socket.receive(buffer)
      if plain = decrypt(buffer[0, count])
        msg = Message.from_io(plain, IO::ByteFormat::NetworkEndian)
        verify_nounce(msg.nounce)
        verify_ts(msg.ts)
        ip_str = ip_to_str(msg.ip)
        verify_ip(ip_str, client_addr) unless client_addr.loopback?
        spawn(name: "") do
          system sprintf(@open_cmd, ip_str)
          sleep 15
          system sprintf(@close_cmd, ip_str)
        end
      end
    rescue ex
      STDERR.puts "ERROR: #{ex.inspect}"
    end
  end

  @seen_nounces = Deque(StaticArray(UInt8, 16)).new(1024)

  private def verify_nounce(nounce)
    raise "nounce seen before" if @seen_nounces.includes? nounce
    @seen_nounces.shift if @seen_nounces.size >= 1024
    @seen_nounces.push nounce
  end

  private def verify_ts(ts)
    raise "timestamp > 10s wrong" if (ts - Time.utc.to_unix_ms).abs > 10_000
  end

  private def ip_to_str(ip)
    String.build(15) do |str|
      ip.each_with_index do |part, i|
        str << "." unless i == 0
        str << part.to_s
      end
    end
  end

  private def verify_ip(ip_str, client_addr)
    raise "source ip doesn't match" if ip_str != client_addr.address
  end

  private def decrypt(data : Bytes) : IO::Memory?
    packet_mac = data[0, 32]
    data += 32
    mac = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, @hmac_key, data)
    return unless mac == packet_mac
    
    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    cipher.decrypt
    cipher.key = @key
    cipher.iv = data[0, cipher.iv_len]
    data += cipher.iv_len
    io = IO::Memory.new(data.bytesize)
    io.write cipher.update(data)
    io.write cipher.final
    io.rewind
    io
  rescue ex
    STDERR.puts "Decrypt failed: #{ex.message}"
    nil
  end
end

key = ""
hmac_key = ""
timeout = 15
case
when File.exists?("/usr/sbin/ufw") # ubuntu
  open_cmd  = "ufw allow from %s to any port 22 proto tcp"
  close_cmd = "ufw delete allow from %s to any port 22 proto tcp"
when File.exists?("/usr/sbin/firewall-cmd") # fedora/centos
  open_cmd = %(firewall-cmd --add-rich-rule='rule family="ipv4" source address="%s" port protocol="tcp" port="22" accept' --timeout=#{timeout})
  close_cmd = ""
else
  open_cmd = close_cmd = ""
end

OptionParser.parse do |parser|
  parser.banner = "Usage: #{PROGRAM_NAME} [arguments]"
  parser.on("-k KEY", "--key=KEY", "Decryption key") { |v| key = v }
  parser.on("-H KEY", "--hmac-key=KEY", "HMAC key") { |v| hmac_key = v }
  parser.on("--open-cmd CMD", "Command to open the firewall, %s will be replace with the IP") do |v|
    open_cmd = v
  end
  parser.on("--close-cmd CMD", "Command to close the firewall, %s will be replace with the IP") do |v|
    close_cmd = v
  end

  parser.on("-h", "--help", "Show this help") do
    puts parser
    exit
  end

  parser.invalid_option do |flag|
    STDERR.puts "ERROR: #{flag} is not a valid option."
    STDERR.puts parser
    exit 1
  end
end

begin
  Server.new(key, hmac_key, open_cmd, close_cmd).listen
rescue ex
  STDERR.puts "ERROR: #{ex.message}"
  exit 1
end
