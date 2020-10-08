require "socket"
require "openssl/cipher"
require "openssl/hmac"
require "./message"
require "./config"

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

begin
  c = Config.new
  Server.new(c.key, c.hmac_key, c.open_cmd, c.close_cmd).listen(c.host, c.port)
rescue ex
  STDERR.puts "ERROR: #{ex.message}"
  exit 1
end
