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

    URLS = [
      "http://ipv6.icanhazip.com",
      "http://ipv4.icanhazip.com",
    ]

    # icanhazip.com is from Cloudflare
    def self.by_http : Array(String)
      with_cache do
        ips = URLS.compact_map do |url|
          resp = HTTP::Client.get(url)
          next unless resp.status_code == 200
          resp.body
        rescue
          nil
        end
        raise "No valid response from icanhazip.com" if ips.empty?
        ips
      end
    end

    CACHE_PATH = ENV.fetch("SPAROID_CACHE_PATH", "/tmp/.sparoid_public_ip")

    private def self.with_cache(&blk : -> Array(String)) : Array(String)
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

    private def self.read_cache : Array(String)
      File.open(CACHE_PATH, "r") do |file|
        file.flock_shared
        file.gets_to_end.split("\n").map(&.strip)
      end
    end

    private def self.write_cache(& : -> Array(String)) : Array(String)
      File.open(CACHE_PATH, "a", 0o0644) do |file|
        file.flock_exclusive
        ips = yield
        file.truncate(0)
        file.rewind
        ips.each do |ip|
          file.puts ip
        end
        ips
      end
    end
  end
end
