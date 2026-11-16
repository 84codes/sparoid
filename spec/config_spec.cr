require "./spec_helper"
require "../src/config"

private def config(str : String) : Sparoid::Config
  Sparoid::Config.new(IO::Memory.new(str))
end

describe Sparoid::Config do
  it "parses a config without sections as a single default profile" do
    c = config <<-INI
      bind = ::
      port = 1234
      key = aa
      hmac-key = bb
      nftables-cmd = add element inet filter sparoid { %s }
      nftablesv6-cmd = add element inet filter sparoid6 { %s }
      INI
    c.host.should eq "::"
    c.port.should eq 1234
    c.profiles.size.should eq 1
    profile = c.profiles.first
    profile.name.should eq ""
    profile.to_s.should eq "default"
    profile.keys.should eq ["aa"]
    profile.hmac_keys.should eq ["bb"]
    profile.nftables?.should be_true
    profile.nftables_cmd.should eq "add element inet filter sparoid { %s }"
    profile.nftablesv6_cmd.should eq "add element inet filter sparoid6 { %s }"
  end

  it "parses each section as its own profile" do
    c = config <<-INI
      bind = ::
      key = aa
      hmac-key = bb
      nftables-cmd = add element inet filter sparoid { %s }

      [postgres]
      key = cc
      hmac-key = dd
      nftables-cmd = add element inet filter sparoid_pg { %s }

      [legacy]
      key = ee
      hmac-key = ff
      open-cmd = open %s
      close-cmd = close %s
      INI
    c.profiles.map(&.name).should eq ["", "postgres", "legacy"]
    pg = c.profiles[1]
    pg.keys.should eq ["cc"]
    pg.hmac_keys.should eq ["dd"]
    pg.nftables_cmd.should eq "add element inet filter sparoid_pg { %s }"
    legacy = c.profiles[2]
    legacy.nftables?.should be_false
    legacy.open_cmd.should eq "open %s"
    legacy.close_cmd.should eq "close %s"
  end

  it "does not need a default profile" do
    c = config <<-INI
      bind = 0.0.0.0
      [postgres]
      key = cc
      hmac-key = dd
      nftables-cmd = add element inet filter sparoid_pg { %s }
      INI
    c.host.should eq "0.0.0.0"
    c.profiles.map(&.name).should eq ["postgres"]
  end

  it "refuses a profile without a command" do
    expect_raises(Sparoid::Config::Error, "Profile 'postgres' has no nftables-cmd") do
      config <<-INI
        key = aa
        hmac-key = bb
        open-cmd = open %s
        [postgres]
        key = cc
        hmac-key = dd
        INI
    end
  end

  it "refuses a profile without keys" do
    expect_raises(Sparoid::Config::Error, "Profile 'postgres' has no key") do
      config <<-INI
        [postgres]
        nftables-cmd = add element inet filter sparoid_pg { %s }
        INI
    end
    expect_raises(Sparoid::Config::Error, "Profile 'default' has no hmac-key") do
      config <<-INI
        key = aa
        open-cmd = open %s
        INI
    end
  end

  it "refuses bind and port inside a section" do
    expect_raises(Sparoid::Config::Error, "'port' is not allowed in section [postgres]") do
      config <<-INI
        [postgres]
        port = 5432
        key = cc
        hmac-key = dd
        open-cmd = open %s
        INI
    end
  end

  it "refuses a config without any keys" do
    expect_raises(Sparoid::Config::Error, "No keys configured") do
      config "bind = ::\n"
    end
  end
end
