require "./spec_helper"
require "../src/ipv6"

describe IPv6 do
  describe ".global?" do
    # Global unicast addresses
    it "returns true for global unicast" do
      IPv6.global?("2607:f8b0:4004:800::200e").should be_true
      IPv6.global?("2400:cb00:2048:1::6814:55").should be_true
    end

    # Non-global addresses
    it "returns false for unspecified (::)" do
      IPv6.global?("::").should be_false
    end

    it "returns false for loopback (::1)" do
      IPv6.global?("::1").should be_false
    end

    it "returns false for IPv4-mapped (::ffff:0:0/96)" do
      IPv6.global?("::ffff:192.168.1.1").should be_false
    end

    it "returns false for link-local (fe80::/10)" do
      IPv6.global?("fe80::1").should be_false
    end

    it "returns false for unique local (fc00::/7)" do
      IPv6.global?("fd00::1").should be_false
      IPv6.global?("fc00::1").should be_false
    end

    it "returns false for multicast (ff00::/8)" do
      IPv6.global?("ff02::1").should be_false
      IPv6.global?("ff05::1").should be_false
    end

    it "returns false for documentation (2001:db8::/32)" do
      IPv6.global?("2001:db8::1").should be_false
    end

    it "returns false for documentation (3fff::/20)" do
      IPv6.global?("3fff:0000::1").should be_false
    end

    it "returns false for 6to4 (2002::/16)" do
      IPv6.global?("2002:c000:0204::1").should be_false
    end

    it "returns false for discard-only (100::/64)" do
      IPv6.global?("0100::1").should be_false
    end

    it "returns false for segment routing (5f00::/16)" do
      IPv6.global?("5f00::1").should be_false
    end

    it "returns false for IETF protocol (2001::/23)" do
      IPv6.global?("2001::1").should be_false
    end

    # Globally reachable sub-ranges within 2001::/23
    it "returns true for AMT (2001:3::/32)" do
      IPv6.global?("2001:3::1").should be_true
    end

    it "returns true for AS112-v6 (2001:4:112::/48)" do
      IPv6.global?("2001:4:112::1").should be_true
    end

    it "returns true for ORCHIDv2 (2001:20::/28)" do
      IPv6.global?("2001:20::1").should be_true
    end

    it "returns false for invalid input" do
      IPv6.global?("not-an-ip").should be_false
    end
  end
end
