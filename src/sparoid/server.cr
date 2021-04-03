require "socket"
require "openssl/cipher"
require "openssl/hmac"
require "./message"

class Server
  @key : Bytes
  @hmac_key : Bytes
  @closed = false

  def initialize(key : String, hmac_key : String, @open_cmd : String, @close_cmd : String)
    @key = key.hexbytes
    @hmac_key = hmac_key.hexbytes
    raise ArgumentError.new("Key must be 32 bytes hex encoded") if @key.bytesize != 32
    raise ArgumentError.new("HMAC key must be 32 bytes hex encoded") if @hmac_key.bytesize != 32
    @socket = UDPSocket.new
  end

  def listen(host, port)
    socket = @socket
    socket.bind host, port
    buffer = Bytes.new(96)
    loop do
      count, client_addr = socket.receive(buffer)
      begin
        raise "Expected UDP packet to be 96 bytes, got #{count} bytes" if count != 96
        packet = buffer[0, count]
        encrypted = verify_packet(packet)
        plain = decrypt(encrypted)
        msg = Message.from_io(plain, IO::ByteFormat::NetworkEndian)
        verify_ts(msg.ts)
        ip_str = ip_to_s(msg.ip)
        verify_ip(ip_str, client_addr) unless client_addr.loopback?
        verify_nounce(msg.nounce)
        puts "#{client_addr} packet accepted"
        spawn open_then_close(ip_str)
      rescue ex
        puts "#{client_addr} ERROR: #{ex.message}"
      end
    end
  rescue ex : IO::Error
    raise ex unless @closed
  end

  def close
    @closed = true
    @socket.close
  end

  private def open_then_close(ip_str)
    system sprintf(@open_cmd, ip_str)
    return if @close_cmd.empty?
    sleep 15
    system sprintf(@close_cmd, ip_str)
  end

  MAX_NOUNCES = 65536 # 65536 * 16 = 1MB
  @seen_nounces = Deque(StaticArray(UInt8, 16)).new(MAX_NOUNCES)

  private def verify_nounce(nounce)
    if @seen_nounces.includes? nounce
      raise "reply-attack, nounce seen before"
    end
    @seen_nounces.shift if @seen_nounces.size == MAX_NOUNCES
    @seen_nounces.push nounce
  end

  MAX_TIMESTAMP_DIFF = 5_000

  private def verify_ts(ts)
    if (Time.utc.to_unix_ms - ts).abs > MAX_TIMESTAMP_DIFF
      raise "timestamp off by more than #{MAX_TIMESTAMP_DIFF.milliseconds.seconds}s"
    end
  end

  private def ip_to_s(ip)
    String.build(15) do |str|
      ip.each_with_index do |part, i|
        str << '.' unless i == 0
        str << part
      end
    end
  end

  private def verify_ip(ip_str, client_addr)
    raise "source ip doesn't match" if ip_str != client_addr.address
  end

  private def verify_packet(data : Bytes) : Bytes
    packet_mac = data[0, 32]
    data += 32
    mac = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, @hmac_key, data)
    raise "HMAC didn't match" unless mac == packet_mac
    data
  end

  private def decrypt(data : Bytes) : IO::Memory
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
  end
end
