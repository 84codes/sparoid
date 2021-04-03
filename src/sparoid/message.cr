require "random/secure"

struct Message
  getter version : Int32, ts : Int64, nounce : StaticArray(UInt8, 16), ip : StaticArray(UInt8, 4)

  def initialize(@version, @ts, @nounce, @ip)
  end

  def initialize(@ip)
    @version = 1
    @ts = Time.utc.to_unix_ms
    @nounce = uninitialized UInt8[16]
    Random::Secure.random_bytes(@nounce.to_slice)
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

  def self.from_io(io, format)
    version = Int32.from_io(io, format)
    ts = Int64.from_io(io, format)
    nounce = uninitialized UInt8[16]
    io.read_fully(nounce.to_slice)
    ip = uninitialized UInt8[4]
    io.read_fully(ip.to_slice)
    self.new(version, ts, nounce, ip)
  end
end
