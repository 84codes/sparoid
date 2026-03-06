require "./spec_helper"

describe Sparoid::Message do
  describe ".from_ip" do
    it "creates message from IPv4 string" do
      msg = Sparoid::Message.from_ip("192.168.1.100")
      msg.family.should eq Socket::Family::INET
      msg.ip_string.should eq "192.168.1.100"
      msg.ip.size.should eq 4
    end

    it "creates message from IPv6 string" do
      msg = Sparoid::Message.from_ip("2001:0db8:85a3::8a2e:0370:7334")
      msg.family.should eq Socket::Family::INET6
      msg.ip_string.should eq "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
      msg.ip.size.should eq 16
    end

    it "strips IPv4-mapped IPv6 to plain IPv4" do
      msg = Sparoid::Message.from_ip("::ffff:192.168.1.1")
      msg.family.should eq Socket::Family::INET
      msg.ip_string.should eq "192.168.1.1"
      msg.ip.size.should eq 4
    end

    it "raises on invalid string" do
      expect_raises(Exception, "Invalid IP address: not-an-ip") do
        Sparoid::Message.from_ip("not-an-ip")
      end
    end
  end

  describe "#ip_string" do
    it "formats localhost" do
      msg = Sparoid::Message.from_ip("127.0.0.1")
      msg.ip_string.should eq "127.0.0.1"
    end

    it "formats 0.0.0.0" do
      msg = Sparoid::Message.from_ip("0.0.0.0")
      msg.ip_string.should eq "0.0.0.0"
    end

    it "formats 255.255.255.255" do
      msg = Sparoid::Message.from_ip("255.255.255.255")
      msg.ip_string.should eq "255.255.255.255"
    end

    it "formats ::1 (loopback)" do
      msg = Sparoid::Message.from_ip("::1")
      msg.ip_string.should eq "0000:0000:0000:0000:0000:0000:0000:0001"
    end

    it "formats :: (all zeros)" do
      msg = Sparoid::Message.from_ip("::")
      msg.ip_string.should eq "0000:0000:0000:0000:0000:0000:0000:0000"
    end

    it "formats 2001:db8::" do
      msg = Sparoid::Message.from_ip("2001:db8::")
      msg.ip_string.should eq "2001:0db8:0000:0000:0000:0000:0000:0000"
    end

    it "formats fe80::1 (link-local)" do
      msg = Sparoid::Message.from_ip("fe80::1")
      msg.ip_string.should eq "fe80:0000:0000:0000:0000:0000:0000:0001"
    end

    it "formats ff02::1 (multicast)" do
      msg = Sparoid::Message.from_ip("ff02::1")
      msg.ip_string.should eq "ff02:0000:0000:0000:0000:0000:0000:0001"
    end
  end

  describe "serialization round-trip" do
    it "serializes and deserializes IPv4" do
      original = Sparoid::Message.from_ip("10.20.30.40")
      slice = original.to_slice(IO::ByteFormat::NetworkEndian)
      slice.size.should eq 32

      io = IO::Memory.new(slice)
      parsed = Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)
      parsed.family.should eq Socket::Family::INET
      parsed.ip_string.should eq "10.20.30.40"
      parsed.ts.should eq original.ts
      parsed.nounce.should eq original.nounce
    end

    it "serializes and deserializes IPv6" do
      original = Sparoid::Message.from_ip("2001:db8::1")
      slice = original.to_slice(IO::ByteFormat::NetworkEndian)
      slice.size.should eq 44

      io = IO::Memory.new(slice)
      parsed = Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)
      parsed.family.should eq Socket::Family::INET6
      parsed.ip_string.should eq "2001:0db8:0000:0000:0000:0000:0000:0001"
      parsed.ts.should eq original.ts
      parsed.nounce.should eq original.nounce
    end

    it "round-trips IPv4-mapped IPv6 as plain IPv4" do
      original = Sparoid::Message.from_ip("::ffff:10.20.30.40")
      slice = original.to_slice(IO::ByteFormat::NetworkEndian)
      slice.size.should eq 32

      io = IO::Memory.new(slice)
      parsed = Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)
      parsed.family.should eq Socket::Family::INET
      parsed.ip_string.should eq "10.20.30.40"
      parsed.ts.should eq original.ts
      parsed.nounce.should eq original.nounce
    end

    it "preserves timestamp and nonce" do
      original = Sparoid::Message.from_ip("1.2.3.4")
      slice = original.to_slice(IO::ByteFormat::NetworkEndian)
      io = IO::Memory.new(slice)
      parsed = Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)
      parsed.ts.should eq original.ts
      parsed.nounce.should eq original.nounce
      parsed.ip.should eq original.ip
    end
  end

  describe ".from_io" do
    it "raises on unsupported version" do
      slice = Bytes.new(32)
      IO::ByteFormat::NetworkEndian.encode(99_i32, slice[0, 4])
      io = IO::Memory.new(slice)
      expect_raises(Exception, "Unsupported message version: 99") do
        Sparoid::Message.from_io(io, IO::ByteFormat::NetworkEndian)
      end
    end
  end

  describe "timestamp and nonce" do
    it "generates unique nonces" do
      msg1 = Sparoid::Message.from_ip("1.2.3.4")
      msg2 = Sparoid::Message.from_ip("1.2.3.4")
      msg1.nounce.should_not eq msg2.nounce
    end

    it "generates timestamps close to current time" do
      before = Time.utc.to_unix_ms
      msg = Sparoid::Message.from_ip("1.2.3.4")
      after = Time.utc.to_unix_ms
      msg.ts.should be >= before
      msg.ts.should be <= after
    end
  end
end
