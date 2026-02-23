require "random/secure"
require "socket"

module Sparoid
  module Message
    abstract struct Base
      getter version : Int32, ts : Int64, nounce : StaticArray(UInt8, 16)

      def initialize(@version)
        @ts = Time.utc.to_unix_ms
        @nounce = uninitialized UInt8[16]
        Random::Secure.random_bytes(@nounce.to_slice)
      end

      def initialize(@version, @ts, @nounce)
      end

      abstract def to_io(io : IO, format : IO::ByteFormat)
      abstract def to_slice(format : IO::ByteFormat) : Bytes
      abstract def ip_string : String
    end

    def self.from_io(io : IO, format : IO::ByteFormat) : Base
      version = Int32.from_io(io, format)
      case version
      when 1
        V1.from_io(io, format)
      when 2
        V2.from_io(io, format)
      else
        raise "Unsupported message version: #{version}"
      end
    end

    def self.ipv4_to_string(ip : Bytes | StaticArray(UInt8, 4), range : UInt8? = nil) : String
      String.build(18) do |str|
        4.times do |i|
          str << '.' unless i == 0
          str << ip[i]
        end
        if range
          str << '/'
          str << range
        end
      end
    end

    def self.ipv6_to_string(ip : Bytes, range : UInt8? = nil) : String
      String.build(43) do |str|
        8.times do |i|
          str << ':' unless i == 0
          str << '0' if ip[i * 2] < 0x10
          ip[i * 2].to_s(str, 16)
          str << '0' if ip[i * 2 + 1] < 0x10
          ip[i * 2 + 1].to_s(str, 16)
        end
        if range
          str << '/'
          str << range
        end
      end
    end

    struct V1 < Base
      getter ip : StaticArray(UInt8, 4)
      getter family = Socket::Family::INET

      def initialize(@ts, @nounce, @ip)
        super(1, @ts, @nounce)
      end

      def initialize(@ip)
        super(1)
      end

      def to_io(io, format)
        io.write_bytes @version, format
        io.write_bytes @ts, format
        io.write @nounce
        io.write @ip
      end

      def to_slice(format : IO::ByteFormat) : Bytes
        slice = Bytes.new(32) # version (4) + timestamp (8) + nounce (16) + ip (4)
        format.encode(@version, slice[0, 4])
        format.encode(@ts, slice[4, 8])
        @nounce.to_slice.copy_to slice[12, @nounce.size]
        @ip.to_slice.copy_to slice[28, @ip.size]
        slice
      end

      def ip_string : String
        Message.ipv4_to_string(@ip)
      end

      def self.from_io(io, format) : V1
        ts = Int64.from_io(io, format)
        nounce = uninitialized UInt8[16]
        io.read_fully(nounce.to_slice)
        ip = uninitialized UInt8[4]
        io.read_fully(ip.to_slice)
        self.new(ts, nounce, ip)
      end
    end

    # V2 messages store IP and range in IPv6 notation.
    # IPv4 addresses are stored as IPv4-mapped IPv6 (::ffff:x.x.x.x) with range + 96.
    struct V2 < Base
      getter ip : StaticArray(UInt8, 16)
      @range : UInt8

      IPV4_PREFIX = StaticArray[0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0xff_u8, 0xff_u8]

      def family : Socket::Family
        ipv4_mapped? ? Socket::Family::INET : Socket::Family::INET6
      end

      def range : UInt8
        ipv4_mapped? ? @range - 96 : @range
      end

      def ipv4_mapped? : Bool
        @ip.to_slice[0, 12] == IPV4_PREFIX.to_slice
      end

      def initialize(@ts, @nounce, @ip, @range)
        super(2, @ts, @nounce)
      end

      def initialize(@ip, @range : UInt8)
        super(2)
      end

      def self.from_ip(ip : StaticArray(UInt8, 4), range : UInt8? = nil) : V2
        sa = StaticArray(UInt8, 16).new(0_u8)
        sa[10] = 0xff_u8
        sa[11] = 0xff_u8
        ip.each_with_index { |byte, i| sa[i + 12] = byte }
        V2.new(sa, (range || 32_u8) + 96)
      end

      def self.from_ip(ip : StaticArray(UInt8, 16), range : UInt8? = nil) : V2
        if ip.to_slice[0, 12] == IPV4_PREFIX.to_slice
          V2.new(ip, (range || 32_u8) + 96)
        else
          V2.new(ip, range || 128_u8)
        end
      end

      def self.from_ip(ip : StaticArray(UInt16, 8), range : UInt8? = nil) : V2
        sa = StaticArray(UInt8, 16).new(0_u8)
        ip.each_with_index do |segment, i|
          IO::ByteFormat::NetworkEndian.encode(segment, sa.to_slice[i * 2, 2])
        end
        if sa.to_slice[0, 12] == IPV4_PREFIX.to_slice
          V2.new(sa, (range || 32_u8) + 96)
        else
          V2.new(sa, range || 128_u8)
        end
      end

      def self.from_ip(ip : Bytes, range : UInt8? = nil) : V2
        case ip.size
        when 4
          from_ip(StaticArray(UInt8, 4).new { |i| ip[i] }, range)
        when 16
          from_ip(StaticArray(UInt8, 16).new { |i| ip[i] }, range)
        else
          raise "IP must be 4 (IPv4) or 16 (IPv6) bytes, got #{ip.size}"
        end
      end

      def self.from_ip(ip : String, range : UInt8? = nil) : V2
        if fields = Socket::IPAddress.parse_v4_fields?(ip)
          from_ip(fields, range)
        elsif fields = Socket::IPAddress.parse_v6_fields?(ip)
          from_ip(fields, range)
        else
          raise "Invalid IP address: #{ip}"
        end
      end

      def to_io(io, format)
        io.write_bytes @version, format
        io.write_bytes @ts, format
        io.write @nounce
        io.write_bytes 6_u8, format
        io.write @ip
        io.write_bytes @range, format
      end

      def to_slice(format : IO::ByteFormat) : Bytes
        slice = Bytes.new(46) # version (4) + timestamp (8) + nounce (16) + family (1) + ip (16) + range (1)
        format.encode(@version, slice[0, 4])
        format.encode(@ts, slice[4, 8])
        @nounce.to_slice.copy_to slice[12, @nounce.size]
        slice[28] = 6_u8
        @ip.to_slice.copy_to(slice[29, 16])
        slice[45] = @range
        slice
      end

      def ip_string : String
        if ipv4_mapped?
          Message.ipv4_to_string(@ip.to_slice[12, 4], range)
        else
          Message.ipv6_to_string(@ip.to_slice, @range)
        end
      end

      def self.from_io(io, format) : V2
        ts = Int64.from_io(io, format)
        nounce = uninitialized UInt8[16]
        io.read_fully(nounce.to_slice)
        family = UInt8.from_io(io, format)
        ip = StaticArray(UInt8, 16).new(0_u8)
        if family == 4_u8
          io.read_fully(ip.to_slice[12, 4])
          ip[10] = 0xff_u8
          ip[11] = 0xff_u8
          range = UInt8.from_io(io, format) + 96
        elsif family == 6_u8
          io.read_fully(ip.to_slice)
          range = UInt8.from_io(io, format)
        else
          raise "Unknown IP family: #{family}"
        end
        self.new(ts, nounce, ip, range)
      end
    end
  end
end
