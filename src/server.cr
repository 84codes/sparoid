require "socket"
require "openssl/cipher"
require "openssl/hmac"
require "./message"

module Sparoid
  class Server
    @keys : Array(Bytes)
    @hmac_keys : Array(Bytes)
    @closed = false

    def initialize(keys : Enumerable(String), hmac_keys : Enumerable(String), @open_cmd : String, @close_cmd : String)
      @keys = keys.map &.hexbytes
      @hmac_keys = hmac_keys.map &.hexbytes
      raise ArgumentError.new("Key must be 32 bytes hex encoded") if @keys.any? { |k| k.bytesize != 32 }
      raise ArgumentError.new("HMAC key must be 32 bytes hex encoded") if @hmac_keys.any? { |k| k.bytesize != 32 }
      @socket = UDPSocket.new
    end

    def bind(host, port)
      @socket.bind host, port
    end

    def listen
      socket = @socket
      packet = Bytes.new(96)
      loop do
        count, client_addr = socket.receive(packet)
        begin
          raise "Expected UDP packet to be 96 bytes, got #{count} bytes" if count != 96
          encrypted = verify_packet(packet)
          plain = decrypt(encrypted)
          msg = Message.from_io(plain, IO::ByteFormat::NetworkEndian)
          verify_ts(msg.ts)
          ip_str = ip_to_s(msg.ip)
          verify_ip(ip_str, client_addr)
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
      ip_str == client_addr.address || raise "source ip doesn't match"
    end

    private def verify_packet(data : Bytes) : Bytes
      packet_mac = data[0, 32]
      data += 32
      @hmac_keys.any? do |hmac_key|
        OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, hmac_key, data) == packet_mac
      end || raise "HMAC didn't match"
      data
    end

    private def decrypt(data : Bytes) : IO::Memory
      cipher = OpenSSL::Cipher.new("aes-256-cbc")
      cipher.decrypt
      cipher.iv = data[0, cipher.iv_len]
      data += cipher.iv_len
      @keys.each do |key|
        cipher.key = key
        io = IO::Memory.new(data.bytesize)
        io.write cipher.update(data)
        io.write cipher.final
        io.rewind
        return io
      rescue
        next
      end
      raise "Could not decrypt payload"
    end
  end
end
