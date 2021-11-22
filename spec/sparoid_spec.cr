require "./spec_helper"

KEYS      = Array(String).new(2) { Random::Secure.hex(32) }
HMAC_KEYS = Array(String).new(2) { Random::Secure.hex(32) }
HOST      = "127.0.0.1"
PORT      = 8484

describe Sparoid::Server do
  it "works" do
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, "", "")
    s.bind(HOST, PORT)
    spawn s.listen
    s.@seen_nounces.size.should eq 0
    Sparoid::Client.send(KEYS.first, HMAC_KEYS.first, HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 1
  ensure
    s.try &.close
  end

  it "fails invalid packet lengths" do
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, "", "")
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
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, "", "")
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
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, "", "")
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
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, "", "")
    s.bind(HOST, PORT)
    spawn s.listen
    s.@seen_nounces.size.should eq 0
    c = Sparoid::Client.new(KEYS.first, HMAC_KEYS.first)
    c.send(HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 1
  ensure
    s.try &.close
  end

  it "works with two keys" do
    s = Sparoid::Server.new(KEYS, HMAC_KEYS, "", "")
    s.bind(HOST, PORT)
    spawn s.listen
    s.@seen_nounces.size.should eq 0
    Sparoid::Client.send(KEYS.first, HMAC_KEYS.first, HOST, PORT)
    Sparoid::Client.send(KEYS.last, HMAC_KEYS.last, HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 2
  ensure
    s.try &.close
  end
end
