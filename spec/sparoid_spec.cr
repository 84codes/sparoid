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
    s.@seen_nounces.size.should eq 2
    last_ip.should eq "127.0.0.1/32"
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
    s.@seen_nounces.size.should eq 2
    accepted.should eq 2
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
    s.@seen_nounces.size.should eq 4
    accepted.should eq 4
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
    Sparoid::Client.send(KEYS.first, HMAC_KEYS.first, "0.0.0.0", address.port, StaticArray[1u8, 1u8, 1u8, 1u8])
    Fiber.yield
    s.@seen_nounces.size.should eq 2
    last_ip.should eq "1.1.1.1/32"
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
    s.@seen_nounces.size.should eq 2
    last_ip.should eq "127.0.0.1/32"
  ensure
    s.try &.close
  end
end
