require "socket"
require "random/secure"
require "openssl/cipher"
require "openssl/hmac"
require "fdpass"
require "./message"
require "./public_ip"
require "ini"
require "./ipv6"

module Sparoid
  class Client
    def self.new(config_path = "~/.sparoid.ini")
      key = ENV.fetch("SPAROID_KEY", "")
      hmac_key = ENV.fetch("SPAROID_HMAC_KEY", "")
      config_path = File.expand_path config_path, home: true
      if File.exists? config_path
        config = File.open(config_path) { |file| INI.parse(file) }
        config.each do |_, section|
          section.each do |k, v|
            case k
            when "key"      then key = v
            when "hmac-key" then hmac_key = v
            end
          end
        end
      end
      self.new(key, hmac_key)
    end

    def initialize(@key : String, @hmac_key : String)
    end

    def send(host : String, port : Int32)
      self.class.send(@key, @hmac_key, host, port)
    end

    def self.send(key : String, hmac_key : String, host : String, port : Int32, ip : StaticArray(UInt8, 4) | StaticArray(UInt8, 16)? = nil) : Array(String)
      udp_send(host, port, key, hmac_key, ip).tap do
        sleep 20.milliseconds # sleep a short while to allow the receiver to parse and execute the packet
      end
    end

    def self.generate_package(key, hmac_key, message : Message::Base) : Bytes
      key = key.hexbytes
      hmac_key = hmac_key.hexbytes
      raise ArgumentError.new("Key must be 32 bytes hex encoded") if key.bytesize != 32
      raise ArgumentError.new("HMAC key must be 32 bytes hex encoded") if hmac_key.bytesize != 32
      encrypt(key, hmac_key, message.to_slice(IO::ByteFormat::NetworkEndian))
    end

    def self.fdpass(ips, port) : NoReturn
      ch = Channel(Nil).new
      ips.each do |ip|
        spawn do
          ipaddr = Socket::IPAddress.new(ip, port)
          socket = TCPSocket.new ipaddr.family
          socket.connect(ipaddr, timeout: 10)
          FDPass.send_fd(1, socket.fd)
          # exit as soon as possible so no other fiber also succefully connects
          exit 0
        rescue
          ch.send(nil)
        end
      end
      ips.size.times { ch.receive }
      exit 1 # only if all connects fails
    end

    # Send to all resolved IPs for the hostname, prioritizing IPv6
    private def self.udp_send(host, port, key : String, hmac_key : String, ip : StaticArray(UInt8, 4) | StaticArray(UInt8, 16)? = nil) : Array(String)
      host_addresses = Socket::Addrinfo.udp(host, port)
      host_addresses.each do |addrinfo|
        packages = generate_messages(addrinfo.ip_address, ip).map { |message| generate_package(key, hmac_key, message) }
        begin
          socket = case addrinfo.family
                   when Socket::Family::INET6
                     UDPSocket.new(Socket::Family::INET6)
                   else
                     UDPSocket.new(Socket::Family::INET)
                   end
          packages.each do |data|
            socket.send data, to: addrinfo.ip_address
          end
        rescue ex
          STDERR << "Sparoid error sending " << ex.inspect << "\n"
        ensure
          socket.try &.close
        end
      end
      host_addresses.map &.ip_address.address
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

    private def self.slice_to_bytes(ip : Slice(UInt16) | Slice(UInt8), format : IO::ByteFormat) : Bytes
      return ip.dup if ip.is_a?(Slice(UInt8))

      buffer = IO::Memory.new(16)
      ip.each do |segment|
        buffer.write_bytes segment, format
      end

      buffer.to_slice
    end

    private def self.generate_messages(host : Socket::IPAddress, ip : StaticArray(UInt8, 4) | StaticArray(UInt8, 16)? = nil) : Array(Message::V2)
      messages = [] of Message::V2
      if ip
        ip_bytes = slice_to_bytes(ip.to_slice, IO::ByteFormat::NetworkEndian)
        messages << Message::V2.from_ip(ip_bytes)
        return messages
      end

      if host.loopback? || host.unspecified?
        ips = local_ips(host)
        ips.each do |i|
          messages << Message::V2.from_ip(i)
        end
        return messages
      end

      ipv6_native = false
      IPv6.public_ipv6_with_range do |ipv6, cidr|
        ipv6_native = true
        messages << Message::V2.from_ip(slice_to_bytes(ipv6.ipv6_addr.to_slice, IO::ByteFormat::NetworkEndian), cidr)
      end

      public_ips = PublicIP.by_http
      public_ips.each do |ip_str|
        if ip = Socket::IPAddress.parse_v4_fields?(ip_str.strip)
          messages << Message::V2.from_ip(slice_to_bytes(ip.to_slice, IO::ByteFormat::NetworkEndian))
        elsif ip = Socket::IPAddress.parse_v6_fields?(ip_str.strip)
          messages << Message::V2.from_ip(slice_to_bytes(ip.to_slice, IO::ByteFormat::NetworkEndian)) unless ipv6_native
        end
      end

      # Sort messages by family to prioritize IPv4 address in case there is a rate limit on the receiver side and it can only process 1 packet / s
      messages.sort_by!(&.family)
      messages
    end

    private def self.local_ips(host : Socket::IPAddress) : Array(Bytes)
      ipv4 = Slice[127u8, 0u8, 0u8, 1u8]
      ipv6 = Slice[
        0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
        0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
        0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
        0x00_u8, 0x00_u8, 0x00_u8, 0x01_u8,
      ]
      if host.family == Socket::Family::INET
        [ipv4]
      else
        [ipv6, ipv4]
      end
    end
  end
end
