require "socket"
require "dns"
require "http/client"

module Sparoid
  class PublicIP
    # https://code.blogs.iiidefix.net/posts/get-public-ip-using-dns/
    def self.by_dns : StaticArray(UInt8, 4)
      socket = UDPSocket.new
      socket.connect("208.67.222.222", 53) # resolver1.opendns.com
      header = DNS::Header.new(op_code: DNS::OpCode::Query, recursion_desired: false)
      message = DNS::Message.new(header: header)
      message.questions << DNS::Question.new(name: DNS::Name.new("myip.opendns.com"), query_type: DNS::RecordType::A)
      message.to_socket socket
      response = DNS::Message.from_socket socket
      data = response.answers.first.data
      case data
      when DNS::IPv4Address
        ip = data.to_slice
        StaticArray(UInt8, 4).new do |i|
          ip[i]
        end
      else raise "Unexpected response type from DNS request: #{data.inspect}"
      end
    ensure
      socket.try &.close
    end

    # ifconfig.co/ip is another option
    def self.by_http : StaticArray(UInt8, 4)
      resp = HTTP::Client.get("http://checkip.amazonaws.com")
      raise "Could not retrive public ip" unless resp.status_code == 200
      str_to_arr resp.body
    end

    private def self.str_to_arr(str) : StaticArray(UInt8, 4)
      ip = StaticArray(UInt8, 4).new(0_u8)
      i = 0
      str.split(".") do |part|
        ip[i += 1] = part.to_u8
      end
      ip
    end
  end
end
