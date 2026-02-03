require "./spec_helper"

describe Sparoid::Message do
  describe "V1" do
    it "creates message with IPv4 address" do
      ip = StaticArray[192_u8, 168_u8, 1_u8, 100_u8]
      msg = Sparoid::Message::V1.new(ip)
      msg.version.should eq 1
      msg.ip.should eq ip
      msg.ip_string.should eq "192.168.1.100"
    end

    it "serializes and deserializes correctly" do
      ip = StaticArray[10_u8, 0_u8, 0_u8, 1_u8]
      original = Sparoid::Message::V1.new(ip)

      # Serialize
      slice = original.to_slice(IO::ByteFormat::NetworkEndian)
      slice.size.should eq 32

      # Deserialize
      io = IO::Memory.new(slice)
      parsed = Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)
      parsed.should be_a(Sparoid::Message::V1)

      v1 = parsed.as(Sparoid::Message::V1)
      v1.version.should eq 1
      v1.ip.should eq ip
      v1.ts.should eq original.ts
      v1.nounce.should eq original.nounce
    end

    it "formats localhost correctly" do
      ip = StaticArray[127_u8, 0_u8, 0_u8, 1_u8]
      msg = Sparoid::Message::V1.new(ip)
      msg.ip_string.should eq "127.0.0.1"
    end

    it "formats 0.0.0.0 correctly" do
      ip = StaticArray[0_u8, 0_u8, 0_u8, 0_u8]
      msg = Sparoid::Message::V1.new(ip)
      msg.ip_string.should eq "0.0.0.0"
    end

    it "formats 255.255.255.255 correctly" do
      ip = StaticArray[255_u8, 255_u8, 255_u8, 255_u8]
      msg = Sparoid::Message::V1.new(ip)
      msg.ip_string.should eq "255.255.255.255"
    end
  end

  describe "V2" do
    describe "#from_ip" do
      it "creates message from IPv4 address" do
        ip = StaticArray[192_u8, 168_u8, 1_u8, 100_u8]
        msg = Sparoid::Message::V2.from_ip(ip.to_slice)
        msg.version.should eq 2
        msg.family.should eq Socket::Family::INET
        msg.range.should eq 32_u8
        msg.ip_string.should eq "192.168.1.100/32"
      end

      it "creates message from IPv4 with custom range" do
        ip = StaticArray[10_u8, 0_u8, 0_u8, 0_u8]
        msg = Sparoid::Message::V2.from_ip(ip.to_slice, 24_u8)
        msg.version.should eq 2
        msg.family.should eq Socket::Family::INET
        msg.range.should eq 24_u8
        msg.ip_string.should eq "10.0.0.0/24"
      end

      it "creates message from full IPv6 address" do
        # 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        ip = StaticArray[
          0x20_u8, 0x01_u8, 0x0d_u8, 0xb8_u8,
          0x85_u8, 0xa3_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x8a_u8, 0x2e_u8,
          0x03_u8, 0x70_u8, 0x73_u8, 0x34_u8,
        ]
        msg = Sparoid::Message::V2.from_ip(ip.to_slice)
        msg.version.should eq 2
        msg.family.should eq Socket::Family::INET6
        msg.range.should eq 128_u8
        msg.ip_string.should eq "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"
      end

      it "creates message from IPv6 with custom range" do
        ip = StaticArray[
          0x20_u8, 0x01_u8, 0x0d_u8, 0xb8_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
        ]
        msg = Sparoid::Message::V2.from_ip(ip.to_slice, 64_u8)
        msg.version.should eq 2
        msg.family.should eq Socket::Family::INET6
        msg.range.should eq 64_u8
      end

      it "formats ::1 (loopback) correctly" do
        ip = StaticArray[
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x01_u8,
        ]
        msg = Sparoid::Message::V2.from_ip(ip.to_slice)
        msg.ip_string.should eq "0000:0000:0000:0000:0000:0000:0000:0001/128"
      end

      it "formats :: (all zeros) correctly" do
        ip = StaticArray(UInt8, 16).new(0_u8)
        msg = Sparoid::Message::V2.from_ip(ip.to_slice)
        msg.ip_string.should eq "0000:0000:0000:0000:0000:0000:0000:0000/128"
      end

      it "formats 2001:db8:: correctly" do
        ip = StaticArray[
          0x20_u8, 0x01_u8, 0x0d_u8, 0xb8_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
        ]
        msg = Sparoid::Message::V2.from_ip(ip.to_slice)
        msg.ip_string.should eq "2001:0db8:0000:0000:0000:0000:0000:0000/128"
      end

      it "formats ::ffff:192.168.1.1 (IPv4-mapped) correctly" do
        # ::ffff:192.168.1.1 = 0000:0000:0000:0000:0000:ffff:c0a8:0101
        ip = StaticArray[
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0xff_u8, 0xff_u8,
          0xc0_u8, 0xa8_u8, 0x01_u8, 0x01_u8,
        ]
        msg = Sparoid::Message::V2.from_ip(ip.to_slice)
        msg.ip_string.should eq "0000:0000:0000:0000:0000:ffff:c0a8:0101/128"
      end

      it "formats fe80::1 (link-local) correctly" do
        ip = StaticArray[
          0xfe_u8, 0x80_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x01_u8,
        ]
        msg = Sparoid::Message::V2.from_ip(ip.to_slice)
        msg.ip_string.should eq "fe80:0000:0000:0000:0000:0000:0000:0001/128"
      end

      it "formats ff02::1 (multicast) correctly" do
        ip = StaticArray[
          0xff_u8, 0x02_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x01_u8,
        ]
        msg = Sparoid::Message::V2.from_ip(ip.to_slice)
        msg.ip_string.should eq "ff02:0000:0000:0000:0000:0000:0000:0001/128"
      end

      it "formats 2001:db8:85a3::8a2e:370:7334 correctly" do
        ip = StaticArray[
          0x20_u8, 0x01_u8, 0x0d_u8, 0xb8_u8,
          0x85_u8, 0xa3_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x8a_u8, 0x2e_u8,
          0x03_u8, 0x70_u8, 0x73_u8, 0x34_u8,
        ]
        msg = Sparoid::Message::V2.from_ip(ip.to_slice)
        msg.ip_string.should eq "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"
      end

      it "formats ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff correctly" do
        ip = StaticArray(UInt8, 16).new(0xff_u8)
        msg = Sparoid::Message::V2.from_ip(ip.to_slice)
        msg.ip_string.should eq "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
      end

      it "raises on invalid IP size" do
        ip = Bytes.new(8) # neither 4 nor 16
        expect_raises(Exception, "IP must be 4 (IPv4) or 16 (IPv6) bytes, got 8") do
          Sparoid::Message::V2.from_ip(ip)
        end
      end
    end

    describe "serialization round-trip" do
      it "serializes and deserializes IPv4 correctly" do
        ip = StaticArray[10_u8, 20_u8, 30_u8, 40_u8]
        original = Sparoid::Message::V2.from_ip(ip.to_slice)

        slice = original.to_slice(IO::ByteFormat::NetworkEndian)
        io = IO::Memory.new(slice)
        parsed = Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)

        parsed.should be_a(Sparoid::Message::V2)
        v2 = parsed.as(Sparoid::Message::V2)
        v2.version.should eq 2
        v2.family.should eq Socket::Family::INET
        v2.range.should eq 32_u8
        v2.ip_string.should eq "10.20.30.40/32"
        v2.ts.should eq original.ts
        v2.nounce.should eq original.nounce
      end

      it "serializes and deserializes IPv4 with custom range" do
        ip = StaticArray[192_u8, 168_u8, 0_u8, 0_u8]
        original = Sparoid::Message::V2.from_ip(ip.to_slice, 16_u8)

        slice = original.to_slice(IO::ByteFormat::NetworkEndian)
        io = IO::Memory.new(slice)
        parsed = Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)

        parsed.should be_a(Sparoid::Message::V2)
        v2 = parsed.as(Sparoid::Message::V2)
        v2.family.should eq Socket::Family::INET
        v2.range.should eq 16_u8
        v2.ip_string.should eq "192.168.0.0/16"
      end

      it "serializes and deserializes IPv6 correctly" do
        ip = StaticArray[
          0xfe_u8, 0x80_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x01_u8,
        ]
        original = Sparoid::Message::V2.from_ip(ip.to_slice)

        slice = original.to_slice(IO::ByteFormat::NetworkEndian)
        io = IO::Memory.new(slice)
        parsed = Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)

        parsed.should be_a(Sparoid::Message::V2)
        v2 = parsed.as(Sparoid::Message::V2)
        v2.version.should eq 2
        v2.family.should eq Socket::Family::INET6
        v2.range.should eq 128_u8
        v2.ip_string.should eq "fe80:0000:0000:0000:0000:0000:0000:0001/128"
        v2.ts.should eq original.ts
        v2.nounce.should eq original.nounce
      end

      it "serializes and deserializes IPv6 with custom range" do
        ip = StaticArray[
          0x20_u8, 0x01_u8, 0x0d_u8, 0xb8_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
        ]
        original = Sparoid::Message::V2.from_ip(ip.to_slice, 48_u8)

        slice = original.to_slice(IO::ByteFormat::NetworkEndian)
        io = IO::Memory.new(slice)
        parsed = Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)

        parsed.should be_a(Sparoid::Message::V2)
        v2 = parsed.as(Sparoid::Message::V2)
        v2.family.should eq Socket::Family::INET6
        v2.range.should eq 48_u8
        v2.ip_string.should eq "2001:0db8:0000:0000:0000:0000:0000:0000/48"
      end

      it "preserves timestamp and nonce through serialization" do
        ip = StaticArray[1_u8, 2_u8, 3_u8, 4_u8]
        original = Sparoid::Message::V2.from_ip(ip.to_slice)

        slice = original.to_slice(IO::ByteFormat::NetworkEndian)
        io = IO::Memory.new(slice)
        parsed = Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)

        parsed.ts.should eq original.ts
        parsed.nounce.should eq original.nounce
        parsed.ip.should eq original.ip
      end
    end

    describe "from_io" do
      it "raises on unknown family in stream" do
        # Manually craft bytes with invalid family (99)
        slice = Bytes.new(46)
        IO::ByteFormat::NetworkEndian.encode(2_i32, slice[0, 4]) # version
        IO::ByteFormat::NetworkEndian.encode(0_i64, slice[4, 8]) # timestamp
        # nounce at [12, 16] - zeros
        slice[28] = 99_u8 # invalid family

        io = IO::Memory.new(slice)
        expect_raises(Exception, "Unknown IP family: 99") do
          Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)
        end
      end
    end
  end

  describe "version detection" do
    it "parses V1 messages" do
      ip = StaticArray[1_u8, 2_u8, 3_u8, 4_u8]
      original = Sparoid::Message::V1.new(ip)
      slice = original.to_slice(IO::ByteFormat::NetworkEndian)

      io = IO::Memory.new(slice)
      parsed = Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)
      parsed.version.should eq 1
      parsed.should be_a(Sparoid::Message::V1)
    end

    it "raises on unsupported version" do
      # Create a fake message with version 99
      slice = Bytes.new(46)
      IO::ByteFormat::NetworkEndian.encode(99_i32, slice[0, 4])

      io = IO::Memory.new(slice)
      expect_raises(Exception, "Unsupported message version: 99") do
        Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)
      end
    end
  end

  describe "timestamp and nonce" do
    it "generates unique nonces" do
      ip = StaticArray[1_u8, 2_u8, 3_u8, 4_u8]
      msg1 = Sparoid::Message::V1.new(ip)
      msg2 = Sparoid::Message::V1.new(ip)
      msg1.nounce.should_not eq msg2.nounce
    end

    it "generates timestamps close to current time" do
      ip = StaticArray[1_u8, 2_u8, 3_u8, 4_u8]
      before = Time.utc.to_unix_ms
      msg = Sparoid::Message::V1.new(ip)
      after = Time.utc.to_unix_ms

      msg.ts.should be >= before
      msg.ts.should be <= after
    end
  end
end
