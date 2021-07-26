require "socket"
require "random/secure"
require "openssl/cipher"
require "openssl/hmac"
require "fdpass"
require "./message"
require "./public_ip"

module Sparoid
  class Client
    def initialize(@key : String, @hmac_key : String, @ip = PublicIP.by_dns)
    end

    def send(host : String, port : Int32)
      self.class.send(@key, @hmac_key, host, port, @ip)
    end

    def self.send(key : String, hmac_key : String, host : String, port : Int32, ip = PublicIP.by_dns)
      key = key.hexbytes
      hmac_key = hmac_key.hexbytes
      raise ArgumentError.new("Key must be 32 bytes hex encoded") if key.bytesize != 32
      raise ArgumentError.new("HMAC key must be 32 bytes hex encoded") if hmac_key.bytesize != 32

      ip = StaticArray[127u8, 0u8, 0u8, 1u8] if {"localhost", "127.0.0.1"}.includes? host
      msg = Message.new(ip)
      data = encrypt(key, hmac_key, msg.to_slice(IO::ByteFormat::NetworkEndian))
      udp_send(host, port, data)
      sleep 0.02 # sleep a short while to allow the receiver to parse and execute the packet
    end

    def self.fdpass(host, port)
      socket = TCPSocket.new(host, port, dns_timeout: 5, connect_timeout: 20)
      FDPass.send_fd(1, socket.fd)
    end

    # Send to all resolved IPs for the hostname
    private def self.udp_send(host, port, data)
      socket = Socket.udp(Socket::Family::INET)
      begin
        Socket::Addrinfo.udp(host, port, Socket::Family::INET).each do |addrinfo|
          begin
            socket.connect addrinfo
            socket.send data
          rescue ex
            STDERR << "Sparoid error sending " << ex.inspect << "\n"
          end
        end
      ensure
        socket.close
      end
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
