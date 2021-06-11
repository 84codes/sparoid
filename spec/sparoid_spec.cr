require "./spec_helper"

KEY = Random::Secure.hex(32)
HMAC_KEY = Random::Secure.hex(32)
HOST = "127.0.0.1"
PORT = 8484

describe Sparoid::Server do
  it "works" do
    s = Sparoid::Server.new(KEY, HMAC_KEY, "", "")
    s.bind(HOST, PORT)
    spawn s.listen
    s.@seen_nounces.size.should eq 0
    Sparoid::Client.send(KEY, HMAC_KEY, HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 1
  ensure
    s.try &.close
  end

  it "fails invalid packet lengths" do
    s = Sparoid::Server.new(KEY, HMAC_KEY, "", "")
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
    s = Sparoid::Server.new(KEY, HMAC_KEY, "", "")
    s.bind(HOST, PORT)
    spawn s.listen
    invalid_key = Random::Secure.hex(32)
    Sparoid::Client.send(invalid_key, HMAC_KEY, HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 0
  ensure
    s.try &.close
  end

  it "fails invalid hmac key" do
    s = Sparoid::Server.new(KEY, HMAC_KEY, "", "")
    s.bind(HOST, PORT)
    spawn s.listen
    invalid_hmac_key = Random::Secure.hex(32)
    Sparoid::Client.send(KEY, invalid_hmac_key, HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 0
  ensure
    s.try &.close
  end
end
