require "socket"

class IPv6
  GOOGLE_DNS = Socket::IPAddress.new("2001:4860:4860::8888", 53)

  # Get the public IPv6 address by asking the OS which source address
  # it would use to reach a well-known IPv6 destination.
  # Returns nil if no global IPv6 address is available.
  def self.public_ipv6 : String?
    socket = UDPSocket.new(Socket::Family::INET6)
    begin
      socket.connect(GOOGLE_DNS)
      addr = socket.local_address
      return addr.address unless addr.loopback? || addr.link_local? || addr.unspecified?
    rescue
    ensure
      socket.close
    end
    nil
  end
end
