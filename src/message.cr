require "random/secure"

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

    struct V2 < Base
      getter ip : Bytes
      getter family : Socket::Family
      getter range : UInt8

      # Add ranges to ip, e.g 192.168.1.1/32 and same for ipv6. /128

      def initialize(@ts, @nounce, @ip, range : UInt8? = nil)
        super(2, @ts, @nounce)
        case @ip.size
        when 4
          if range && range > 32
            raise "Invalid range for IPv4: #{range}, must be between 0 and 32"
          end
          @range = range || 32u8
          @family = Socket::Family::INET
        when 16
          if range && range > 128
            raise "Invalid range for IPv6: #{range}, must be between 0 and 128"
          end
          @range = range || 128u8
          @family = Socket::Family::INET6
        else
          raise "IP must be 4 (IPv4) or 16 (IPv6) bytes, got #{@ip.size}"
        end
      end

      def initialize(@ip, range : UInt8? = nil)
        super(2)
        case @ip.size
        when 4
          if range && range > 32
            raise "Invalid range for IPv4: #{range}, must be between 0 and 32"
          end
          @range = range || 32u8
          @family = Socket::Family::INET
        when 16
          if range && range > 128
            raise "Invalid range for IPv6: #{range}, must be between 0 and 128"
          end
          @range = range || 128u8
          @family = Socket::Family::INET6
        else
          raise "IP must be 4 (IPv4) or 16 (IPv6) bytes, got #{@ip.size}"
        end
      end

      def self.from_ip(ip : Bytes, range : UInt8? = nil) : V2
        V2.new(ip, range)
      end

      def to_io(io, format)
        io.write_bytes @version, format
        io.write_bytes @ts, format
        io.write @nounce
        io.write_bytes @family == Socket::Family::INET ? 4u8 : 6u8, format
        io.write @ip
        io.write_bytes @range, format
      end

      def to_slice(format : IO::ByteFormat) : Bytes
        slice = Bytes.new(46) # version (4) + timestamp (8) + nounce (16) + family (1) + ip (16) + range (1)
        format.encode(@version, slice[0, 4])
        format.encode(@ts, slice[4, 8])
        @nounce.to_slice.copy_to slice[12, @nounce.size]
        slice[28] = @family == Socket::Family::INET ? 4_u8 : 6_u8
        @ip.copy_to slice[29, @ip.size]
        slice[29 + @ip.size] = @range
        slice
      end

      def ip_string : String
        case @family
        when Socket::Family::INET
          Message.ipv4_to_string(@ip, @range)
        when Socket::Family::INET6
          Message.ipv6_to_string(@ip, @range)
        else
          raise "Unknown IP family: #{@family}"
        end
      end

      def self.from_io(io, format) : V2
        ts = Int64.from_io(io, format)
        nounce = uninitialized UInt8[16]
        io.read_fully(nounce.to_slice)
        family = UInt8.from_io(io, format)
        ip = if family == 4_u8
               Bytes.new(4)
             elsif family == 6_u8
               Bytes.new(16)
             else
               raise "Unknown IP family: #{family}"
             end
        io.read_fully(ip.to_slice)
        range = UInt8.from_io(io, format)
        self.new(ts, nounce, ip, range)
      end
    end
  end
end
