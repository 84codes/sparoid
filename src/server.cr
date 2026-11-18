require "socket"
require "openssl/cipher"
require "openssl/hmac"
require "crypto/subtle"
require "./message"

module Sparoid
  class Server
    alias AcceptProc = Proc(String, Socket::Family, Nil)

    # A set of keys and the action to run when a packet is authenticated by one of them.
    # Which profile a packet belongs to is decided by which HMAC key authenticates it,
    # so that different keys can open up for different services.
    class Profile
      getter name : String
      getter keys : Array(Bytes)
      getter hmac_keys : Array(Bytes)
      getter on_accept : AcceptProc

      def initialize(@name : String, keys : Enumerable(String), hmac_keys : Enumerable(String), @on_accept : AcceptProc)
        @keys = keys.map { |k| k.hexbytes? || raise ArgumentError.new("Key must be 32 bytes hex encoded") }.to_a
        @hmac_keys = hmac_keys.map { |k| k.hexbytes? || raise ArgumentError.new("HMAC key must be 32 bytes hex encoded") }.to_a
        raise ArgumentError.new("Key must be 32 bytes hex encoded") if @keys.any? { |k| k.bytesize != 32 }
        raise ArgumentError.new("HMAC key must be 32 bytes hex encoded") if @hmac_keys.any? { |k| k.bytesize != 32 }
      end

      def to_s(io : IO) : Nil
        io << (@name.empty? ? "default" : @name)
      end
    end

    @profiles : Array(Profile)

    def initialize(profiles : Enumerable(Profile), @address : Socket::IPAddress)
      @profiles = self.class.validate(profiles)
      @socket = UDPSocket.new(@address.family)
    end

    # Replace the profiles of a running server, eg. when the config is reloaded.
    # Raises and keeps the current profiles if the new ones are invalid.
    # The nonce cache is kept, so packets can't be replayed after a reload.
    def profiles=(profiles : Enumerable(Profile))
      @profiles = self.class.validate(profiles)
    end

    protected def self.validate(profiles : Enumerable(Profile)) : Array(Profile)
      profiles = profiles.to_a
      seen = Set(Bytes).new
      profiles.each do |profile|
        profile.hmac_keys.each do |hmac_key|
          seen.add?(hmac_key) || raise ArgumentError.new("HMAC key used more than once, each HMAC key must be unique (profile '#{profile}')")
        end
      end
      profiles
    end

    def self.new(keys : Enumerable(String), hmac_keys : Enumerable(String), on_accept : AcceptProc, address : Socket::IPAddress)
      new({Profile.new("", keys, hmac_keys, on_accept)}, address)
    end

    def bind
      @socket.bind @address
    end

    def listen
      socket = @socket
      packet = Bytes.new(96)
      loop do
        count, client_addr = socket.receive(packet)
        begin
          ip_str, profile = authenticate_and_accept(packet, count)
          log = "#{client_addr} packet accepted"
          log += " profile=#{profile}" unless profile.name.empty?
          log += " ip=#{ip_str}" if ip_str != client_addr.address
          puts log
        rescue ex
          puts "#{client_addr} ERROR: #{ex.message}"
        end
      end
    rescue ex : IO::Error
      raise ex unless @socket.closed?
    end

    def process_packet(packet : Bytes, count : Int) : String
      authenticate_and_accept(packet, count).first
    end

    private def authenticate_and_accept(packet : Bytes, count : Int) : {String, Profile}
      raise "Expected UDP packet to be 96 bytes, got #{count} bytes" if count != 96
      encrypted, profile = verify_packet(packet)
      plain = decrypt(encrypted, profile)
      msg = Message.from_io(plain, IO::ByteFormat::NetworkEndian)
      verify_ts(msg.ts)
      verify_nounce(msg.nounce)
      ip_str = msg.ip_string
      profile.on_accept.call(ip_str, msg.family)
      {ip_str, profile}
    end

    def close
      @socket.close
    end

    MAX_NOUNCES = 65536 # 65536 * 16 = 1MB
    @seen_nounces = Deque(StaticArray(UInt8, 16)).new(MAX_NOUNCES)

    private def verify_nounce(nounce)
      if @seen_nounces.includes? nounce
        raise "replay-attack, nounce seen before"
      end
      @seen_nounces.shift if @seen_nounces.size >= MAX_NOUNCES
      @seen_nounces.push nounce
    end

    MAX_TIMESTAMP_DIFF = 5_000

    private def verify_ts(ts)
      if (Time.utc.to_unix_ms - ts).abs > MAX_TIMESTAMP_DIFF
        raise "timestamp off by more than #{MAX_TIMESTAMP_DIFF.milliseconds.seconds}s"
      end
    end

    # Returns the encrypted payload and the profile whose HMAC key authenticated the packet
    private def verify_packet(data : Bytes) : {Bytes, Profile}
      packet_mac = data[0, 32]
      data += 32
      @profiles.each do |profile|
        profile.hmac_keys.each do |hmac_key|
          return {data, profile} if Crypto::Subtle.constant_time_compare(hmac_digest(hmac_key, data), packet_mac)
        end
      end
      raise "HMAC didn't match"
    end

    @cipher = OpenSSL::Cipher.new("aes-256-cbc")
    @io = IO::Memory.new(32)

    private def decrypt(data : Bytes, profile : Profile) : IO::Memory
      @cipher.reset
      @cipher.decrypt
      @cipher.iv = data[0, @cipher.iv_len]
      data += @cipher.iv_len
      profile.keys.each do |key|
        @cipher.key = key
        @io.clear
        @io.write @cipher.update(data)
        @io.write @cipher.final
        @io.rewind
        return @io
      rescue
        next
      end
      raise "Could not decrypt payload"
    end

    SHA256_EVP = OpenSSL::Algorithm::SHA256.to_evp
    @hmac_buffer = Bytes.new(32)

    private def hmac_digest(key, data) : Bytes
      key_slice = key.to_slice
      data_slice = data.to_slice
      LibCrypto.hmac(SHA256_EVP, key_slice, key_slice.size, data_slice, data_slice.size, @hmac_buffer, out buffer_len)
      buffer_len == 32 || raise "Unexpected hmac digest length #{buffer_len}"
      @hmac_buffer
    end
  end
end
