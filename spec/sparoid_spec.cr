require "./spec_helper"
require "socket"

KEYS      = Array(String).new(2) { Random::Secure.hex(32) }
HMAC_KEYS = Array(String).new(2) { Random::Secure.hex(32) }
ADDRESS   = Socket::IPAddress.new("127.0.0.1", 8484)

describe Sparoid::Server do
  it "works" do
    last_ip = nil
    cb = ->(ip : String, _family : Socket::Family) { last_ip = ip }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb, ADDRESS)
    s.bind
    spawn s.listen
    s.@seen_nounces.size.should eq 0
    Sparoid::Client.send(KEYS.first, HMAC_KEYS.first, ADDRESS.address, ADDRESS.port)
    Fiber.yield
    s.@seen_nounces.size.should eq 1
    last_ip.should eq "127.0.0.1"
  ensure
    s.try &.close
  end

  it "fails invalid packet lengths" do
    cb = ->(ip : String, _family : Socket::Family) { ip.should be_nil }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb, ADDRESS)
    s.bind
    spawn s.listen
    socket = UDPSocket.new
    socket.connect ADDRESS.address, ADDRESS.port
    socket.send Bytes.new(8)
    socket.close
    Fiber.yield
    s.@seen_nounces.size.should eq 0
  ensure
    s.try &.close
  end

  it "fails invalid key" do
    cb = ->(ip : String, _family : Socket::Family) { ip.should be_nil }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb, ADDRESS)
    s.bind
    spawn s.listen
    invalid_key = Random::Secure.hex(32)
    Sparoid::Client.send(invalid_key, HMAC_KEYS.first, ADDRESS.address, ADDRESS.port)
    Fiber.yield
    s.@seen_nounces.size.should eq 0
  ensure
    s.try &.close
  end

  it "fails invalid hmac key" do
    cb = ->(ip : String, _family : Socket::Family) { ip.should be_nil }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb, ADDRESS)
    s.bind
    spawn s.listen
    invalid_hmac_key = Random::Secure.hex(32)
    Sparoid::Client.send(KEYS.first, invalid_hmac_key, ADDRESS.address, ADDRESS.port)
    Fiber.yield
    s.@seen_nounces.size.should eq 0
  ensure
    s.try &.close
  end

  it "client can cache IP" do
    accepted = 0
    cb = ->(_ip : String, _family : Socket::Family) { accepted += 1 }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb, ADDRESS)
    s.bind
    spawn s.listen
    s.@seen_nounces.size.should eq 0
    c = Sparoid::Client.new(KEYS.first, HMAC_KEYS.first)
    c.send(ADDRESS.address, ADDRESS.port)
    Fiber.yield
    s.@seen_nounces.size.should eq 1
    accepted.should eq 1
  ensure
    s.try &.close
  end

  it "works with two keys" do
    accepted = 0
    cb = ->(_ip : String, _family : Socket::Family) { accepted += 1 }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb, ADDRESS)
    s.bind
    spawn s.listen
    s.@seen_nounces.size.should eq 0
    Sparoid::Client.send(KEYS.first, HMAC_KEYS.first, ADDRESS.address, ADDRESS.port)
    Sparoid::Client.send(KEYS.last, HMAC_KEYS.last, ADDRESS.address, ADDRESS.port)
    Fiber.yield
    s.@seen_nounces.size.should eq 2
    accepted.should eq 2
  ensure
    s.try &.close
  end

  it "client can send another IP" do
    last_ip = nil
    cb = ->(ip : String, _family : Socket::Family) { last_ip = ip }
    address = Socket::IPAddress.new("0.0.0.0", ADDRESS.port)
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb, address)
    s.bind
    spawn s.listen
    Sparoid::Client.send(KEYS.first, HMAC_KEYS.first, "0.0.0.0", address.port, "1.1.1.1")
    Fiber.yield
    s.@seen_nounces.size.should eq 1
    last_ip.should eq "1.1.1.1"
  ensure
    s.try &.close
  end

  it "can parse manually constructed messages" do
    last_ip = nil
    cb = ->(ip : String, _family : Socket::Family) { last_ip = ip }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb, ADDRESS)
    s.bind
    spawn s.listen
    msg = Sparoid::Message.from_ip("127.0.0.1")
    data = Sparoid::Client.generate_package(KEYS.first, HMAC_KEYS.first, msg)
    socket = UDPSocket.new
    socket.send data, to: ADDRESS
    socket.close
    Fiber.yield
    s.@seen_nounces.size.should eq 1
    last_ip.should eq "127.0.0.1"
  ensure
    s.try &.close
  end

  it "can accept IPv4 connections on ::" do
    last_ip = nil
    cb = ->(ip : String, _family : Socket::Family) { last_ip = ip }
    address = Socket::IPAddress.new("::", ADDRESS.port)
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb, address)
    s.bind
    spawn s.listen
    Sparoid::Client.send(KEYS.first, HMAC_KEYS.first, "127.0.0.1", address.port)
    Fiber.yield
    s.@seen_nounces.size.should eq 1
    last_ip.should eq "127.0.0.1"
  ensure
    s.try &.close
  end

  describe "profiles" do
    it "runs only the action of the profile whose key authenticated the packet" do
      ssh = [] of String
      pg = [] of String
      profiles = [
        Sparoid::Server::Profile.new("", [KEYS.first], [HMAC_KEYS.first], ->(ip : String, _family : Socket::Family) { ssh << ip; nil }),
        Sparoid::Server::Profile.new("postgres", [KEYS.last], [HMAC_KEYS.last], ->(ip : String, _family : Socket::Family) { pg << ip; nil }),
      ]
      s = Sparoid::Server.new(profiles, ADDRESS)
      s.bind
      spawn s.listen
      Sparoid::Client.send(KEYS.last, HMAC_KEYS.last, ADDRESS.address, ADDRESS.port)
      Fiber.yield
      ssh.should be_empty
      pg.should eq ["127.0.0.1"]
      Sparoid::Client.send(KEYS.first, HMAC_KEYS.first, ADDRESS.address, ADDRESS.port)
      Fiber.yield
      ssh.should eq ["127.0.0.1"]
      pg.should eq ["127.0.0.1"]
    ensure
      s.try &.close
    end

    it "rejects a packet that mixes the keys of two profiles" do
      accepted = 0
      cb = ->(_ip : String, _family : Socket::Family) { accepted += 1; nil }
      profiles = [
        Sparoid::Server::Profile.new("", [KEYS.first], [HMAC_KEYS.first], cb),
        Sparoid::Server::Profile.new("postgres", [KEYS.last], [HMAC_KEYS.last], cb),
      ]
      s = Sparoid::Server.new(profiles, ADDRESS)
      s.bind
      spawn s.listen
      Sparoid::Client.send(KEYS.first, HMAC_KEYS.last, ADDRESS.address, ADDRESS.port)
      Sparoid::Client.send(KEYS.last, HMAC_KEYS.first, ADDRESS.address, ADDRESS.port)
      Fiber.yield
      accepted.should eq 0
      s.@seen_nounces.size.should eq 0
    ensure
      s.try &.close
    end

    it "rejects a replayed packet when several profiles are configured" do
      accepted = 0
      cb = ->(_ip : String, _family : Socket::Family) { accepted += 1; nil }
      profiles = [
        Sparoid::Server::Profile.new("", [KEYS.first], [HMAC_KEYS.first], cb),
        Sparoid::Server::Profile.new("postgres", [KEYS.last], [HMAC_KEYS.last], cb),
      ]
      s = Sparoid::Server.new(profiles, ADDRESS)
      data = Sparoid::Client.generate_package(KEYS.last, HMAC_KEYS.last, Sparoid::Message.from_ip("127.0.0.1"))
      s.process_packet(data, data.size).should eq "127.0.0.1"
      expect_raises(Exception, "replay-attack") { s.process_packet(data, data.size) }
      accepted.should eq 1
    ensure
      s.try &.close
    end

    it "can replace its profiles while running, keeping the nonce cache" do
      accepted = [] of String
      s = Sparoid::Server.new([KEYS.first], [HMAC_KEYS.first], ->(_ip : String, _family : Socket::Family) { accepted << "old"; nil }, ADDRESS)
      old = Sparoid::Client.generate_package(KEYS.first, HMAC_KEYS.first, Sparoid::Message.from_ip("127.0.0.1"))
      s.process_packet(old, old.size)
      cb = ->(_ip : String, _family : Socket::Family) { accepted << "new"; nil }
      s.profiles = [
        Sparoid::Server::Profile.new("", [KEYS.first], [HMAC_KEYS.first], cb),
        Sparoid::Server::Profile.new("postgres", [KEYS.last], [HMAC_KEYS.last], cb),
      ]
      expect_raises(Exception, "replay-attack") { s.process_packet(old, old.size) }
      data = Sparoid::Client.generate_package(KEYS.last, HMAC_KEYS.last, Sparoid::Message.from_ip("127.0.0.1"))
      s.process_packet(data, data.size)
      accepted.should eq ["old", "new"]
    ensure
      s.try &.close
    end

    it "keeps its profiles if the new ones are invalid" do
      accepted = 0
      cb = ->(_ip : String, _family : Socket::Family) { accepted += 1; nil }
      s = Sparoid::Server.new([KEYS.first], [HMAC_KEYS.first], cb, ADDRESS)
      expect_raises(ArgumentError, "HMAC key used more than once") do
        s.profiles = [
          Sparoid::Server::Profile.new("", [KEYS.last], [HMAC_KEYS.last], cb),
          Sparoid::Server::Profile.new("postgres", [KEYS.last], [HMAC_KEYS.last], cb),
        ]
      end
      data = Sparoid::Client.generate_package(KEYS.first, HMAC_KEYS.first, Sparoid::Message.from_ip("127.0.0.1"))
      s.process_packet(data, data.size)
      accepted.should eq 1
    ensure
      s.try &.close
    end

    it "refuses the same HMAC key in two profiles" do
      cb = ->(_ip : String, _family : Socket::Family) { nil }
      profiles = [
        Sparoid::Server::Profile.new("", [KEYS.first], [HMAC_KEYS.first], cb),
        Sparoid::Server::Profile.new("postgres", [KEYS.last], [HMAC_KEYS.first], cb),
      ]
      expect_raises(ArgumentError, "HMAC key used more than once") do
        Sparoid::Server.new(profiles, ADDRESS)
      end
    end
  end

  it "doesn't include a malformed key in the error" do
    cb = ->(_ip : String, _family : Socket::Family) { }
    bad = "not-a-hex-key-#{Random::Secure.hex(8)}"
    ex = expect_raises(ArgumentError, "Key must be 32 bytes hex encoded") do
      Sparoid::Server.new([bad], HMAC_KEYS, cb, ADDRESS)
    end
    ex.message.to_s.should_not contain bad
    ex = expect_raises(ArgumentError, "HMAC key must be 32 bytes hex encoded") do
      Sparoid::Server.new(KEYS, [bad], cb, ADDRESS)
    end
    ex.message.to_s.should_not contain bad
  end

  it "rejects a packet with a tampered HMAC" do
    accepted = 0
    cb = ->(_ip : String, _family : Socket::Family) { accepted += 1; nil }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb, ADDRESS)
    data = Sparoid::Client.generate_package(KEYS.first, HMAC_KEYS.first, Sparoid::Message.from_ip("127.0.0.1"))
    data[31] ^= 1
    expect_raises(Exception, "HMAC didn't match") { s.process_packet(data, data.size) }
    accepted.should eq 0
  ensure
    s.try &.close
  end
end

describe Sparoid::Client do
  it "doesn't include a malformed key in the error" do
    bad = "not-a-hex-key-#{Random::Secure.hex(8)}"
    ex = expect_raises(ArgumentError, "Key must be 32 bytes hex encoded") do
      Sparoid::Client.generate_package(bad, HMAC_KEYS.first, Sparoid::Message.from_ip("127.0.0.1"))
    end
    ex.message.to_s.should_not contain bad
  end

  describe ".process_send_results" do
    it "raises SendError when every send failed" do
      ip1 = Socket::IPAddress.new("1.1.1.1", 1)
      ip2 = Socket::IPAddress.new("2.2.2.2", 2)
      results = [
        {ip1, Exception.new("no route").as(Exception?)},
        {ip2, Exception.new("network down").as(Exception?)},
      ]
      ex = expect_raises(Sparoid::Client::SendError) do
        Sparoid::Client.process_send_results("example.com", results)
      end
      ex.message.to_s.should contain("example.com")
      ex.message.to_s.should contain("1.1.1.1:1: no route")
      ex.message.to_s.should contain("2.2.2.2:2: network down")
    end

    it "returns partial-failure errors when at least one send succeeded" do
      ip1 = Socket::IPAddress.new("1.1.1.1", 1)
      ip2 = Socket::IPAddress.new("2.2.2.2", 2)
      err = Exception.new("oops")
      results = [
        {ip1, nil.as(Exception?)},
        {ip2, err.as(Exception?)},
      ]
      Sparoid::Client.process_send_results("example.com", results).should eq [{ip2, err}]
    end

    it "returns nothing when all sends succeeded" do
      ip = Socket::IPAddress.new("1.1.1.1", 1)
      results = [{ip, nil.as(Exception?)}]
      Sparoid::Client.process_send_results("example.com", results).should be_empty
    end

    it "returns nothing when there were no addresses" do
      Sparoid::Client.process_send_results("example.com", [] of {Socket::IPAddress, Exception?}).should be_empty
    end
  end
end
