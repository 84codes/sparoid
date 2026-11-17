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
      key = #{"aa" * 32}
      hmac-key = #{"bb" * 32}
      nftables-cmd = add element inet filter sparoid { %s }
      nftablesv6-cmd = add element inet filter sparoid6 { %s }
      INI
    c.host.should eq "::"
    c.port.should eq 1234
    c.profiles.size.should eq 1
    profile = c.profiles.first
    profile.name.should eq ""
    profile.to_s.should eq "default"
    profile.keys.should eq ["aa" * 32]
    profile.hmac_keys.should eq ["bb" * 32]
    profile.nftables?.should be_true
    profile.nftables_cmd.should eq "add element inet filter sparoid { %s }"
    profile.nftablesv6_cmd.should eq "add element inet filter sparoid6 { %s }"
  end

  it "parses each section as its own profile" do
    c = config <<-INI
      bind = ::
      key = #{"aa" * 32}
      hmac-key = #{"bb" * 32}
      nftables-cmd = add element inet filter sparoid { %s }

      [postgres]
      key = #{"cc" * 32}
      hmac-key = #{"dd" * 32}
      nftables-cmd = add element inet filter sparoid_pg { %s }

      [legacy]
      key = #{"ee" * 32}
      hmac-key = #{"ff" * 32}
      open-cmd = open %s
      close-cmd = close %s
      INI
    c.profiles.map(&.name).should eq ["", "postgres", "legacy"]
    pg = c.profiles[1]
    pg.keys.should eq ["cc" * 32]
    pg.hmac_keys.should eq ["dd" * 32]
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
      key = #{"cc" * 32}
      hmac-key = #{"dd" * 32}
      nftables-cmd = add element inet filter sparoid_pg { %s }
      INI
    c.host.should eq "0.0.0.0"
    c.profiles.map(&.name).should eq ["postgres"]
  end

  it "refuses a profile without a command" do
    expect_raises(Sparoid::Config::Error, "Profile 'postgres' has no nftables-cmd") do
      config <<-INI
        key = #{"aa" * 32}
        hmac-key = #{"bb" * 32}
        open-cmd = open %s
        [postgres]
        key = #{"cc" * 32}
        hmac-key = #{"dd" * 32}
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
        key = #{"aa" * 32}
        open-cmd = open %s
        INI
    end
  end

  it "refuses a top level with a command but no keys" do
    expect_raises(Sparoid::Config::Error, "Profile 'default' has no key") do
      config <<-INI
        bind = ::
        nftables-cmd = add element inet filter sparoid { %s }
        [postgres]
        key = #{"cc" * 32}
        hmac-key = #{"dd" * 32}
        nftables-cmd = add element inet filter sparoid_pg { %s }
        INI
    end
  end

  it "refuses a [default] section, it is the name of the top level" do
    expect_raises(Sparoid::Config::Error, "Section [Default] is reserved") do
      config <<-INI
        [Default]
        key = #{"cc" * 32}
        hmac-key = #{"dd" * 32}
        open-cmd = open %s
        INI
    end
  end

  it "refuses bind and port inside a section" do
    expect_raises(Sparoid::Config::Error, "'port' is not allowed in section [postgres]") do
      config <<-INI
        [postgres]
        port = 5432
        key = #{"cc" * 32}
        hmac-key = #{"dd" * 32}
        open-cmd = open %s
        INI
    end
  end

  it "refuses a config without any keys" do
    expect_raises(Sparoid::Config::Error, "No keys configured") do
      config "bind = ::\n"
    end
  end

  it "refuses keys that aren't 32 bytes hex encoded" do
    expect_raises(Sparoid::Config::Error, "Profile 'default': key must be 32 bytes hex encoded") do
      config <<-INI
        key = #{"aa" * 33}
        hmac-key = #{"bb" * 32}
        open-cmd = open %s
        INI
    end
    expect_raises(Sparoid::Config::Error, "Profile 'postgres': hmac-key must be 32 bytes hex encoded") do
      config <<-INI
        [postgres]
        key = #{"aa" * 32}
        hmac-key = #{"zz" * 32}
        open-cmd = open %s
        INI
    end
  end

  it "refuses the same HMAC key in two profiles" do
    expect_raises(Sparoid::Config::Error, "Profile 'postgres': hmac-key is already used") do
      config <<-INI
        key = #{"aa" * 32}
        hmac-key = #{"bb" * 32}
        open-cmd = open %s
        [postgres]
        key = #{"cc" * 32}
        hmac-key = #{"BB" * 32}
        open-cmd = open %s
        INI
    end
  end

  it "refuses an invalid bind address or port" do
    expect_raises(Sparoid::Config::Error, "Invalid bind address 'localhost'") do
      config "bind = localhost\n"
    end
    expect_raises(Sparoid::Config::Error, "Invalid port '8484x'") do
      config "port = 8484x\n"
    end
    expect_raises(Sparoid::Config::Error, "Invalid port '65536'") do
      config "port = 65536\n"
    end
  end

  it "refuses a command that isn't a valid format string" do
    expect_raises(Sparoid::Config::Error, "Profile 'default': nftables-cmd is not a valid format string") do
      config <<-INI
        key = #{"aa" * 32}
        hmac-key = #{"bb" * 32}
        nftables-cmd = add element inet filter sparoid { %s } comment "100%"
        INI
    end
  end

  it "warns about unknown settings and commands without %s" do
    c = config <<-INI
      key = #{"aa" * 32}
      hmac-key = #{"bb" * 32}
      open-cmd = open
      close_cmd = close %s
      [postgres]
      key = #{"cc" * 32}
      hmac-key = #{"dd" * 32}
      nftables-cmd = add element inet filter sparoid_pg { %s }
      nftable-cmd = typo
      INI
    c.warnings.should eq [
      "Unknown setting 'close_cmd' at the top of the file, ignored",
      "Profile 'default': open-cmd has no %s, the IP won't be part of the command",
      "Unknown setting 'nftable-cmd' in section [postgres], ignored",
    ]
  end

  it "has no warnings for a valid config" do
    c = config <<-INI
      key = #{"aa" * 32}
      hmac-key = #{"bb" * 32}
      nftables-cmd = add element inet filter sparoid { %s }
      INI
    c.warnings.should be_empty
  end

  it "loads a config file" do
    file = File.tempfile("sparoid", ".ini") do |io|
      io.puts "key = #{"aa" * 32}", "hmac-key = #{"bb" * 32}", "open-cmd = open %s"
    end
    Sparoid::Config.load(file.path).profiles.size.should eq 1
    File.write(file.path, "bind = ::\n")
    expect_raises(Sparoid::Config::Error, "No keys configured") { Sparoid::Config.load(file.path) }
  ensure
    file.try &.delete
  end
end
