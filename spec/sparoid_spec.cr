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
end

describe Sparoid::Client do
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
