require "socket"

lib LibC
  struct IfAddrs
    ifa_next : IfAddrs*     # ameba:disable Lint/UselessAssign
    ifa_name : Char*        # ameba:disable Lint/UselessAssign
    ifa_flags : UInt32      # ameba:disable Lint/UselessAssign
    ifa_addr : Sockaddr*    # ameba:disable Lint/UselessAssign
    ifa_netmask : Sockaddr* # ameba:disable Lint/UselessAssign
    ifa_dstaddr : Sockaddr* # ameba:disable Lint/UselessAssign
    ifa_data : Void*        # ameba:disable Lint/UselessAssign
  end

  fun getifaddrs(ifap : IfAddrs**) : Int32
  fun freeifaddrs(ifa : IfAddrs*)
end

class Socket
  struct IPAddress < Address
    # Monkey patch to expose address_value
    def address_value
      previous_def
    end

    def ipv6_addr
      if family != Family::INET6
        raise "Socket::IPAddress is not IPv6"
      end

      ipv6_addr8(@addr.as(LibC::In6Addr))
    end
  end
end

class IPv6
  # Helper to count bits in the netmask (Calculates the /64, /128, etc.)
  private def self.count_cidr(netmask_ptr : Pointer(LibC::Sockaddr)) : UInt8
    return 0_u8 if netmask_ptr.null?

    ipaddress = Socket::IPAddress.from(netmask_ptr, sizeof(LibC::SockaddrIn6))
    ipaddress.address_value.popcount.to_u8
  end

  def self.public_ipv6_with_range(& : (Socket::IPAddress, UInt8, String) -> Nil)
    ifap = Pointer(LibC::IfAddrs).null

    if LibC.getifaddrs(pointerof(ifap)) == -1
      raise "Failed to get interface addresses"
    end

    begin
      current = ifap
      while current
        unless current.value.ifa_addr.null?
          family = current.value.ifa_addr.value.sa_family

          if family == LibC::AF_INET6
            # 1. Get the Single IP
            ip = Socket::IPAddress.from(current.value.ifa_addr, sizeof(LibC::SockaddrIn6))
            if ip.nil? || ip.loopback? || ip.link_local? || ip.unspecified? || ip.private?
              current = current.value.ifa_next
              next
            end

            # 2. Get the Netmask CIDR (The range size)
            cidr = count_cidr(current.value.ifa_netmask)

            yield ip, cidr, String.new(current.value.ifa_name)
          end
        end
        current = current.value.ifa_next
      end
    ensure
      LibC.freeifaddrs(ifap)
    end
  end
end
