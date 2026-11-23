require "./spec_helper"
require "file_utils"

V4_ICANHAZIP = "https://ipv4.icanhazip.com"
V4_AMAZON    = "https://checkip.amazonaws.com"
V4_IPIFY     = "https://api.ipify.org"
V6_ICANHAZIP = "https://ipv6.icanhazip.com"
V6_IPIFY     = "https://api6.ipify.org"

# Stubs the HTTP fetch, a missing URL or a nil response raises like a failed request
private def with_providers(responses : Hash(String, String?), &)
  calls = [] of String
  cache = File.tempname("sparoid_public_ip_spec")
  original_fetcher = Sparoid::PublicIP.fetcher
  original_cache_path = Sparoid::PublicIP.cache_path
  Sparoid::PublicIP.fetcher = ->(url : String) do
    calls << url
    responses[url]? || raise "request to #{url} failed"
  end
  Sparoid::PublicIP.cache_path = cache
  begin
    yield calls, cache
  ensure
    Sparoid::PublicIP.fetcher = original_fetcher
    Sparoid::PublicIP.cache_path = original_cache_path
    FileUtils.rm_rf(cache)
  end
end

describe Sparoid::PublicIP do
  it "falls back in order for IPv4 until a provider answers" do
    with_providers({V4_IPIFY => "198.51.100.4\n"}) do |calls|
      Sparoid::PublicIP.first_valid(Sparoid::PublicIP::IPV4_URLS) { |ip| Socket::IPAddress.valid_v4?(ip) }
        .should eq "198.51.100.4"
      calls.should eq [V4_ICANHAZIP, V4_AMAZON, V4_IPIFY]
    end
  end

  it "stops at the first valid answer and skips invalid ones" do
    with_providers({V4_ICANHAZIP => "<html>", V4_AMAZON => "203.0.113.9\n", V4_IPIFY => "198.51.100.4"}) do |calls|
      Sparoid::PublicIP.ipv4.should eq "203.0.113.9"
      calls.should_not contain V4_IPIFY
      calls.select(&.in?(Sparoid::PublicIP::IPV4_URLS)).should eq [V4_ICANHAZIP, V4_AMAZON]
    end
  end

  it "falls back for IPv6 and rejects non-global addresses" do
    with_providers({V6_ICANHAZIP => "fe80::1", V6_IPIFY => "2606:4700:4700::1111\n", V4_ICANHAZIP => "203.0.113.9"}) do |calls|
      Sparoid::PublicIP.ipv6.should eq "2606:4700:4700::1111"
      calls.select(&.in?(Sparoid::PublicIP::IPV6_URLS)).should eq [V6_ICANHAZIP, V6_IPIFY]
    end
  end

  it "doesn't cache a failed lookup" do
    with_providers({} of String => String?) do |calls, cache|
      expect_raises(Exception, /No valid response/) { Sparoid::PublicIP.by_http }
      calls.size.should eq 5
      File.size(cache).should eq 0
      expect_raises(Exception, /No valid response/) { Sparoid::PublicIP.by_http }
      calls.size.should eq 10
    end
  end

  it "caches a successful lookup" do
    responses = {V4_ICANHAZIP => "203.0.113.9"} of String => String?
    with_providers(responses) do |calls, cache|
      Sparoid::PublicIP.ipv4.should eq "203.0.113.9"
      File.read(cache).should eq "203.0.113.9\n"
      responses[V4_ICANHAZIP] = "198.51.100.4"
      Sparoid::PublicIP.ipv4.should eq "203.0.113.9"
      calls.count(V4_ICANHAZIP).should eq 1
    end
  end
end
