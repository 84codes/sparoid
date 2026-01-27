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

    struct V1 < Base
      getter ip : StaticArray(UInt8, 4)

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
        String.build(15) do |str|
          @ip.each_with_index do |part, i|
            str << '.' unless i == 0
            str << part
          end
        end
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
      getter family : UInt8
      getter ip : StaticArray(UInt8, 16) | StaticArray(UInt8, 4)

      def initialize(@ts, @nounce, @family, @ip)
        super(2, @ts, @nounce)
      end

      def initialize(@family, @ip)
        super(2)
      end

      # Create V2 from IPv4 StaticArray
      def self.from_ip(ip : StaticArray(UInt8, 4) | StaticArray(UInt8, 16)) : V2
        family = case ip.size
                 when  4 then 4_u8
                 when 16 then 6_u8
                 else
                   raise ArgumentError.new("IP must be StaticArray of 4 (IPv4) or 16 (IPv6) bytes")
                 end
        V2.new(family, ip)
      end

      def to_io(io, format)
        io.write_bytes @version, format
        io.write_bytes @ts, format
        io.write @nounce
        io.write_bytes @family, format
        io.write @ip
      end

      def to_slice(format : IO::ByteFormat) : Bytes
        slice = Bytes.new(45) # version (4) + timestamp (8) + nounce (16) + family (1) + ip (16)
        format.encode(@version, slice[0, 4])
        format.encode(@ts, slice[4, 8])
        @nounce.to_slice.copy_to slice[12, @nounce.size]
        slice[28] = @family
        @ip.to_slice.copy_to slice[29, @ip.size]
        slice
      end

      def ip_string : String
        case @family
        when 4_u8
          # IPv4: first 4 bytes
          String.build(15) do |str|
            4.times do |i|
              str << '.' unless i == 0
              str << @ip[i]
            end
          end
        when 6_u8
          # IPv6: all 16 bytes as hex pairs with colons
          String.build(39) do |str|
            8.times do |i|
              str << ':' unless i == 0
              str << @ip[i * 2].to_s(16).rjust(2, '0')
              str << @ip[i * 2 + 1].to_s(16).rjust(2, '0')
            end
          end
        else
          raise "Unknown IP family: #{@family}"
        end
      end

      def self.from_io(io, format) : V2
        ts = Int64.from_io(io, format)
        nounce = uninitialized UInt8[16]
        io.read_fully(nounce.to_slice)
        family = UInt8.from_io(io, format)
        ip = uninitialized UInt8[16]
        io.read_fully(ip.to_slice)
        self.new(ts, nounce, family, ip)
      end
    end
  end
end
