require "./spec_helper"

KEYS      = Array(String).new(2) { Random::Secure.hex(32) }
HMAC_KEYS = Array(String).new(2) { Random::Secure.hex(32) }
HOST      = "127.0.0.1"
PORT      = 8484

describe Sparoid::Server do
  it "works" do
    last_ip = nil
    cb = ->(ip : String) { last_ip = ip }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb)
    s.bind(HOST, PORT)
    spawn s.listen
    s.@seen_nounces.size.should eq 0
    Sparoid::Client.send(KEYS.first, HMAC_KEYS.first, HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 1
    last_ip.should eq "127.0.0.1"
  ensure
    s.try &.close
  end

  it "fails invalid packet lengths" do
    cb = ->(ip : String) { ip.should be_nil }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb)
    s.bind(HOST, PORT)
    spawn s.listen
    socket = UDPSocket.new
    socket.connect HOST, PORT
    socket.send Bytes.new(8)
    socket.close
    Fiber.yield
    s.@seen_nounces.size.should eq 0
  ensure
    s.try &.close
  end

  it "fails invalid key" do
    cb = ->(ip : String) { ip.should be_nil }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb)
    s.bind(HOST, PORT)
    spawn s.listen
    invalid_key = Random::Secure.hex(32)
    Sparoid::Client.send(invalid_key, HMAC_KEYS.first, HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 0
  ensure
    s.try &.close
  end

  it "fails invalid hmac key" do
    cb = ->(ip : String) { ip.should be_nil }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb)
    s.bind(HOST, PORT)
    spawn s.listen
    invalid_hmac_key = Random::Secure.hex(32)
    Sparoid::Client.send(KEYS.first, invalid_hmac_key, HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 0
  ensure
    s.try &.close
  end

  it "client can cache IP" do
    accepted = 0
    cb = ->(_ip : String) { accepted += 1 }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb)
    s.bind(HOST, PORT)
    spawn s.listen
    s.@seen_nounces.size.should eq 0
    c = Sparoid::Client.new(KEYS.first, HMAC_KEYS.first)
    c.send(HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 1
    accepted.should eq 1
  ensure
    s.try &.close
  end

  it "works with two keys" do
    accepted = 0
    cb = ->(_ip : String) { accepted += 1 }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb)
    s.bind(HOST, PORT)
    spawn s.listen
    s.@seen_nounces.size.should eq 0
    Sparoid::Client.send(KEYS.first, HMAC_KEYS.first, HOST, PORT)
    Sparoid::Client.send(KEYS.last, HMAC_KEYS.last, HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 2
    accepted.should eq 2
  ensure
    s.try &.close
  end

  it "client can send another IP" do
    last_ip = nil
    cb = ->(ip : String) { last_ip = ip }
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, cb)
    s.bind("0.0.0.0", PORT)
    spawn s.listen
    Sparoid::Client.send(KEYS.first, HMAC_KEYS.first, "0.0.0.0", PORT, StaticArray[1u8, 1u8, 1u8, 1u8])
    Fiber.yield
    s.@seen_nounces.size.should eq 1
    last_ip.should eq "1.1.1.1"
  ensure
    s.try &.close
  end
end
