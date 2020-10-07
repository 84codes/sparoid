require "random/secure"

struct Message
  getter version : Int32, ts : Int64, nounce : StaticArray(UInt8, 16), ip : StaticArray(UInt8, 4)

  def initialize(@version, @ts, @nounce, @ip)
  end

  def initialize
    @version = 1
    @ts = Time.utc.to_unix_ms
    @nounce = StaticArray(UInt8, 16).new { Random::Secure.next_u }
    @ip = public_ip
  end

  def public_ip
    resp = HTTP::Client.get("https://checkip.amazonaws.com")
    raise "Could not retrive public ip" unless resp.status_code == 200
    myip = resp.body

    ip = StaticArray(UInt8, 4).new(0_u8)
    myip.split(".").each_with_index do |part, i|
      ip[i] = part.to_u8
    end
    ip
  end

  def to_io(io, format)
    io.write_bytes @version, format
    io.write_bytes @ts, format
    io.write @nounce
    io.write @ip
  end

  def to_slice(format : IO::ByteFormat) : Bytes
    slice = Bytes.new(sizeof(Int32) + sizeof(Int64) + @nounce.size + @ip.size)
    format.encode(@version, slice[0, 4])
    format.encode(@ts, slice[4, 8])
    @nounce.to_slice.copy_to slice[12, @nounce.size]
    @ip.to_slice.copy_to slice[28, @ip.size]
    slice
  end

  def self.from_io(io, format)
    version = Int32.from_io(io, format)
    ts = Int64.from_io(io, format)
    nounce = StaticArray(UInt8, 16).new do |i|
      io.read_byte || raise IO::EOFError.new
    end
    ip = StaticArray(UInt8, 4).new do |i|
      io.read_byte || raise IO::EOFError.new
    end
    self.new(version, ts, nounce, ip)
  end
end
