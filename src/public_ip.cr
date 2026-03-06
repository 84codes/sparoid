require "socket"
require "dns"
require "http/client"

module Sparoid
  class PublicIP
    URLS = {
      "http://ipv6.icanhazip.com",
      "http://ipv4.icanhazip.com",
    }

    def self.ipv4 : String?
      by_http.find { |ip| !ip.includes?(':') }
    end

    def self.ipv6 : String?
      by_http.find { |ip| ip.includes?(':') }
    end

    # icanhazip.com is from Cloudflare
    # returns stripped IP addresses as strings, one per URL in URLS
    def self.by_http : Array(String)
      with_cache do
        ips = URLS.compact_map do |url|
          resp = HTTP::Client.get(url)
          next unless resp.status_code == 200
          resp.body.chomp
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
        Array(String).new.tap do |ips|
          while line = file.gets
            ips << line
          end
        end
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
