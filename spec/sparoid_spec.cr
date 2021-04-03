require "./spec_helper"

KEY = Random::Secure.hex(32)
HMAC_KEY = Random::Secure.hex(32)
HOST = "localhost"
PORT = 8484

describe Server do
  it "works" do
    s = Server.new(KEY, HMAC_KEY, "", "")
    spawn s.listen(HOST, PORT)
    s.@seen_nounces.size.should eq 0
    Client.send(KEY, HMAC_KEY, HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 1
    s.close
  end

  it "fails invalid packet lengths" do
    s = Server.new(KEY, HMAC_KEY, "", "")
    spawn s.listen(HOST, PORT)
    socket = UDPSocket.new
    socket.connect HOST, PORT
    socket.send Bytes.new(8)
    socket.close
    Fiber.yield
    s.@seen_nounces.size.should eq 0
    s.close
  end

  it "fails invalid key" do
    s = Server.new(KEY, HMAC_KEY, "", "")
    spawn s.listen(HOST, PORT)
    invalid_key = Random::Secure.hex(32)
    Client.send(invalid_key, HMAC_KEY, HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 0
    s.close
  end

  it "fails invalid hmac key" do
    s = Server.new(KEY, HMAC_KEY, "", "")
    spawn s.listen(HOST, PORT)
    invalid_hmac_key = Random::Secure.hex(32)
    Client.send(KEY, invalid_hmac_key, HOST, PORT)
    Fiber.yield
    s.@seen_nounces.size.should eq 0
    s.close
  end
end
