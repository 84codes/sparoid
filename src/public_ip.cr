require "socket"
require "http/client"
require "wait_group"
require "./ipv6"

module Sparoid
  class PublicIP
    IPV4_URLS = {
      "https://ipv4.icanhazip.com",
      "https://checkip.amazonaws.com",
      "https://api.ipify.org",
    }
    IPV6_URLS = {
      "https://ipv6.icanhazip.com",
      "https://api6.ipify.org",
    }
    URLS = IPV6_URLS + IPV4_URLS

    class_property fetcher : Proc(String, String) = ->(url : String) { PublicIP.http_get(url) }

    def self.ipv4 : String?
      by_http.find { |ip| !ip.includes?(':') }
    end

    def self.ipv6 : String?
      by_http.find(&.includes?(':'))
    end

    # returns the public IPv6 and IPv4 address, whichever could be found
    def self.by_http : Array(String)
      with_cache do
        ipv6 = ipv4 = nil.as(String?)
        wg = WaitGroup.new
        wg.spawn { ipv6 = first_valid(IPV6_URLS) { |ip| Socket::IPAddress.valid_v6?(ip) && IPv6.global?(ip) } }
        wg.spawn { ipv4 = first_valid(IPV4_URLS) { |ip| Socket::IPAddress.valid_v4?(ip) } }
        wg.wait
        ips = [ipv6, ipv4].compact
        raise "No valid response from any public IP provider" if ips.empty?
        ips
      end
    end

    # Tries the URLs one at a time, the next only if the previous failed
    def self.first_valid(urls, & : String -> Bool) : String?
      urls.each do |url|
        ip = fetcher.call(url).strip
        return ip if yield ip
      rescue
        next
      end
      nil
    end

    def self.http_get(url : String) : String
      uri = URI.parse(url)
      HTTP::Client.new(uri) do |client|
        client.connect_timeout = 3.seconds
        client.read_timeout = 5.seconds
        resp = client.get(uri.request_target)
        raise "#{url} responded #{resp.status_code}" unless resp.status_code == 200
        resp.body
      end
    end

    CACHE_PATH = ENV.fetch("SPAROID_CACHE_PATH", "/tmp/.sparoid_public_ip")

    class_property cache_path : String = CACHE_PATH

    private def self.with_cache(&blk : -> Array(String)) : Array(String)
      if up_to_date_cache?
        read_cache
      else
        write_cache(&blk)
      end
    end

    private def self.up_to_date_cache? : Bool
      if info = File.info?(cache_path)
        return info.size > 0 && (Time.utc - info.modification_time) <= 60.seconds
      end
      false
    end

    private def self.read_cache : Array(String)
      File.open(cache_path, "r") do |file|
        file.flock_shared
        Array(String).new.tap do |ips|
          while line = file.gets
            line = line.strip
            ips << line unless line.empty?
          end
        end
      end
    end

    private def self.write_cache(& : -> Array(String)) : Array(String)
      File.open(cache_path, "a", 0o0644) do |file|
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
