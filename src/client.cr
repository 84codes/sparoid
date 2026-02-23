require "socket"
require "random/secure"
require "openssl/cipher"
require "openssl/hmac"
require "fdpass"
require "./message"
require "./public_ip"
require "ini"
require "./ipv6"
require "wait_group"

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

    def self.send(key : String, hmac_key : String, host : String, port : Int32, public_ip = nil) : Array(String)
      udp_send(host, port, key, hmac_key, public_ip).tap do
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
      wg = WaitGroup.new
      ips.each do |ip|
        wg.spawn do
          ipaddr = Socket::IPAddress.new(ip, port)
          socket = TCPSocket.new ipaddr.family
          socket.connect(ipaddr, timeout: 10)
          FDPass.send_fd(1, socket.fd)
          exit 0 # exit as soon as possible so no other fiber also succefully connects
        end
      end
      wg.wait
      exit 1 # only if all connects fails
    end

    # Send to all resolved IPs for the hostname, prioritizing IPv6
    private def self.udp_send(host, port, key : String, hmac_key : String, public_ip = nil) : Array(String)
      host_addresses = Socket::Addrinfo.udp(host, port)
      host_addresses.each do |addrinfo|
        packages = generate_messages(addrinfo.ip_address, public_ip).map { |message| generate_package(key, hmac_key, message) }
        socket = UDPSocket.new(addrinfo.family)
        begin
          packages.each do |data|
            socket.send data, to: addrinfo.ip_address
          end
        rescue ex
          STDERR << "Sparoid error sending " << ex.inspect << "\n"
        ensure
          socket.close
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

    # Generate messages for all local IPs and public IPs.
    # Look up public IPs via HTTP if public ip is not provided as an argument.
    # If the host is loopback or unspecified, only generate for local IPs since the receiver won't be able to connect back to the public IPs.
    private def self.generate_messages(host : Socket::IPAddress, public_ip : StaticArray? = nil) : Array(Message::V2)
      return [Message::V2.from_ip(public_ip)] if public_ip
      return local_ips(host).map { |ip| Message::V2.from_ip(ip) } if host.loopback? || host.unspecified?

      messages = Array(Message::V2).new
      ipv6_native = false
      IPv6.public_ipv6_with_range do |ipv6, cidr|
        ipv6_native = true
        messages << Message::V2.from_ip(ipv6.ipv6_addr, cidr)
      end

      PublicIP.by_http.each do |ip_str|
        if ipv4 = Socket::IPAddress.parse_v4_fields?(ip_str)
          messages << Message::V2.from_ip(ipv4)
        elsif ipv6 = Socket::IPAddress.parse_v6_fields?(ip_str)
          messages << Message::V2.from_ip(ipv6) unless ipv6_native
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
