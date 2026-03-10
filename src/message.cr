require "random/secure"
require "socket"

module Sparoid
  struct Message
    VERSION = 1_i32

    getter ts : Int64, nounce : StaticArray(UInt8, 16), ip : Bytes

    def initialize(@ts, @nounce, @ip : Bytes)
    end

    def initialize(@ip : Bytes)
      @ts = Time.utc.to_unix_ms
      @nounce = uninitialized UInt8[16]
      Random::Secure.random_bytes(@nounce.to_slice)
    end

    def family : Socket::Family
      @ip.size == 4 ? Socket::Family::INET : Socket::Family::INET6
    end

    def ip_string : String
      if @ip.size == 4
        String.build(15) do |str|
          4.times do |i|
            str << '.' unless i == 0
            str << @ip[i]
          end
        end
      else
        String.build(39) do |str|
          8.times do |i|
            str << ':' unless i == 0
            str << '0' if @ip[i * 2] < 0x10
            @ip[i * 2].to_s(str, 16)
            str << '0' if @ip[i * 2 + 1] < 0x10
            @ip[i * 2 + 1].to_s(str, 16)
          end
        end
      end
    end

    def to_slice(format : IO::ByteFormat) : Bytes
      size = 28 + @ip.size # version (4) + timestamp (8) + nounce (16) + ip (4 or 16)
      slice = Bytes.new(size)
      format.encode(VERSION, slice[0, 4])
      format.encode(@ts, slice[4, 8])
      @nounce.to_slice.copy_to(slice[12, 16])
      @ip.copy_to(slice[28, @ip.size])
      slice
    end

    def self.from_io(io : IO, format : IO::ByteFormat) : Message
      version = Int32.from_io(io, format)
      raise "Unsupported message version: #{version}" unless version == VERSION
      ts = Int64.from_io(io, format)
      nounce = uninitialized UInt8[16]
      io.read_fully(nounce.to_slice)
      buf = Bytes.new(16)
      count = io.read(buf)
      raise "Invalid IP: expected 4 or 16 bytes, got #{count}" unless count == 4 || count == 16
      Message.new(ts, nounce, strip_mapped_ipv4(buf[0, count]))
    end

    def self.from_ip(ip : String) : Message
      if fields = Socket::IPAddress.parse_v4_fields?(ip)
        Message.new(Bytes[fields[0], fields[1], fields[2], fields[3]])
      elsif fields = Socket::IPAddress.parse_v6_fields?(ip)
        ip_bytes = Bytes.new(16)
        fields.each_with_index do |segment, i|
          IO::ByteFormat::NetworkEndian.encode(segment, ip_bytes[i * 2, 2])
        end
        Message.new(strip_mapped_ipv4(ip_bytes))
      else
        raise "Invalid IP address: #{ip}"
      end
    end

    # Convert ::ffff:x.x.x.x (IPv4-mapped IPv6) to plain 4-byte IPv4
    private def self.strip_mapped_ipv4(ip : Bytes) : Bytes
      if ip.size == 16 &&
         ip[0, 12] == Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
        ip[12, 4].dup
      else
        ip.dup
      end
    end
  end
end
