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
      return addr.address if global?(addr.address)
    rescue
    ensure
      socket.close
    end
    nil
  end

  # Check if an IPv6 address is globally reachable.
  # Based on Rust std::net::Ipv6Addr::is_global (IETF RFC 4291, RFC 6890, etc.)
  # ameba:disable Metrics/CyclomaticComplexity
  def self.global?(ip : String) : Bool
    s = Socket::IPAddress.parse_v6_fields?(ip)
    return false unless s
    return false if unspecified?(s) || loopback?(s)
    return false if ipv4_mapped?(s)
    return false if ipv4_ipv6_translation?(s)
    return false if discard_only?(s)
    return false if ietf_protocol_non_global?(s)
    return false if sixto4?(s)
    return false if documentation?(s)
    return false if segment_routing?(s)
    return false if unique_local?(s)
    return false if link_local?(s)
    true
  end

  private def self.unspecified?(s) : Bool
    s == StaticArray[0u16, 0, 0, 0, 0, 0, 0, 0]
  end

  private def self.loopback?(s) : Bool
    s == StaticArray[0u16, 0, 0, 0, 0, 0, 0, 1]
  end

  # ::ffff:0:0/96
  private def self.ipv4_mapped?(s) : Bool
    s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0xffff
  end

  # 64:ff9b:1::/48
  private def self.ipv4_ipv6_translation?(s) : Bool
    s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1
  end

  # 100::/64
  private def self.discard_only?(s) : Bool
    s[0] == 0x100 && s[1] == 0 && s[2] == 0 && s[3] == 0
  end

  # 2001::/23 minus globally reachable sub-ranges
  # ameba:disable Metrics/CyclomaticComplexity
  private def self.ietf_protocol_non_global?(s) : Bool
    return false unless s[0] == 0x2001 && s[1] < 0x200
    # PCP/TURN Anycast (2001:1::1, 2001:1::2)
    return false if s[1] == 1 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 && s[6] == 0 && (s[7] == 1 || s[7] == 2)
    return false if s[1] == 3                    # AMT (2001:3::/32)
    return false if s[1] == 4 && s[2] == 0x112   # AS112-v6 (2001:4:112::/48)
    return false if s[1] >= 0x20 && s[1] <= 0x3f # ORCHIDv2 / Drone DETs
    true
  end

  # 2002::/16
  private def self.sixto4?(s) : Bool
    s[0] == 0x2002
  end

  # 2001:db8::/32, 3fff:0000::/20
  private def self.documentation?(s) : Bool
    (s[0] == 0x2001 && s[1] == 0xdb8) || (s[0] == 0x3fff && s[1] <= 0x0fff)
  end

  # 5f00::/16
  private def self.segment_routing?(s) : Bool
    s[0] == 0x5f00
  end

  # fc00::/7
  private def self.unique_local?(s) : Bool
    s[0] & 0xfe00 == 0xfc00
  end

  # fe80::/10
  private def self.link_local?(s) : Bool
    s[0] & 0xffc0 == 0xfe80
  end
end
