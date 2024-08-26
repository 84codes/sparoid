require "socket"
require "dns"
require "http/client"

module Sparoid
  class PublicIP
    # https://code.blogs.iiidefix.net/posts/get-public-ip-using-dns/
    def self.by_dns : StaticArray(UInt8, 4)
      with_cache do
        socket = UDPSocket.new
        socket.connect("208.67.222.222", 53) # resolver1.opendns.com
        header = DNS::Header.new(op_code: DNS::OpCode::Query, recursion_desired: false)
        message = DNS::Message.new(header: header)
        message.questions << DNS::Question.new(name: DNS::Name.new("myip.opendns.com"), query_type: DNS::RecordType::A)
        message.to_socket socket
        response = DNS::Message.from_socket socket
        if answer = response.answers.first?
          data = answer.data
          case data
          when DNS::IPv4Address
            ip = data.to_slice
            StaticArray(UInt8, 4).new do |i|
              ip[i]
            end
          else raise "Unexpected response type from DNS request: #{data.inspect}"
          end
        else
          raise "No A response from myip.opendns.com"
        end
      ensure
        socket.try &.close
      end
    end

    # ifconfig.co/ip is another option
    def self.by_http : StaticArray(UInt8, 4)
      with_cache do
        resp = HTTP::Client.get("http://checkip.amazonaws.com")
        raise "Could not retrive public ip" unless resp.status_code == 200
        str_to_arr resp.body
      end
    end

    private def self.str_to_arr(str : String) : StaticArray(UInt8, 4)
      ip = StaticArray(UInt8, 4).new(0_u8)
      i = 0
      str.split(".") do |part|
        ip[i] = part.to_u8
        i += 1
      end
      ip
    end

    CACHE_PATH = ENV.fetch("SPAROID_CACHE_PATH", "/tmp/.sparoid_public_ip")

    private def self.with_cache(&blk : -> StaticArray(UInt8, 4)) : StaticArray(UInt8, 4)
      if up_to_date_cache?
        read_cache
      else
        write_cache(&blk)
      end
    end

    private def self.up_to_date_cache? : Bool
      if mtime = File.info?(CACHE_PATH).try(&.modification_time)
        return (Time.utc - mtime) <= 60.seconds
      end
      false
    end

    private def self.read_cache : StaticArray(UInt8, 4)
      File.open(CACHE_PATH, "r") do |file|
        file.flock_shared
        str_to_arr(file.gets_to_end)
      end
    end

    private def self.write_cache(& : -> StaticArray(UInt8, 4)) : StaticArray(UInt8, 4)
      File.open(CACHE_PATH, "a", 0o0644) do |file|
        file.flock_exclusive
        ip = yield
        file.truncate
        ip.each_with_index do |e, i|
          file.print '.' unless i.zero?
          file.print e
        end
        ip
      end
    end
  end
end
