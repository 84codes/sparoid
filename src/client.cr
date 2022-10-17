require "socket"
require "random/secure"
require "openssl/cipher"
require "openssl/hmac"
require "fdpass"
require "./message"
require "./public_ip"
require "ini"

module Sparoid
  class Client
    def self.new(config_path = "~/.sparoid.ini")
      key = ENV.fetch("SPAROID_KEY", "")
      hmac_key = ENV.fetch("SPAROID_HMAC_KEY", "")
      config_path = File.expand_path config_path, home: true
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
      self.new(key, hmac_key)
    end

    def initialize(@key : String, @hmac_key : String, @ip = PublicIP.by_dns)
    end

    def send(host : String, port : Int32)
      self.class.send(@key, @hmac_key, host, port, @ip)
    end

    def self.send(key : String, hmac_key : String, host : String, port : Int32, ip = PublicIP.by_dns) : Array(String)
      ip = StaticArray[127u8, 0u8, 0u8, 1u8] if {"localhost", "127.0.0.1"}.includes? host
      package = generate_package(key, hmac_key, ip)
      udp_send(host, port, package).tap do
        sleep 0.02 # sleep a short while to allow the receiver to parse and execute the packet
      end
    end

    def self.generate_package(key, hmac_key, ip) : Bytes
      key = key.hexbytes
      hmac_key = hmac_key.hexbytes
      raise ArgumentError.new("Key must be 32 bytes hex encoded") if key.bytesize != 32
      raise ArgumentError.new("HMAC key must be 32 bytes hex encoded") if hmac_key.bytesize != 32

      msg = Message.new(ip)
      encrypt(key, hmac_key, msg.to_slice(IO::ByteFormat::NetworkEndian))
    end

    def self.fdpass(ips, port) : NoReturn
      ch = Channel(Nil).new
      ips.each do |ip|
        spawn do
          socket = TCPSocket.new
          socket.connect(Socket::IPAddress.new(ip, port), timeout: 10)
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

    # Send to all resolved IPs for the hostname
    private def self.udp_send(host, port, data) : Array(String)
      host_addresses = Socket::Addrinfo.udp(host, port, Socket::Family::INET)
      socket = Socket.udp(Socket::Family::INET, blocking: true)
      host_addresses.each do |addrinfo|
        begin
          socket.send data, to: addrinfo.ip_address
        rescue ex
          STDERR << "Sparoid error sending " << ex.inspect << "\n"
        end
      end
      host_addresses.map &.ip_address.address
    ensure
      socket.close if socket
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
end
