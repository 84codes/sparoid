require "option_parser"
require "ini"
require "socket"
require "./version"

module Sparoid
  class Config
    class Error < Exception; end

    # Keys and the commands to run when a packet is authenticated by one of them.
    # The top level of the config file is the unnamed default profile,
    # each [section] is a named profile.
    class Profile
      getter name : String
      getter keys = Array(String).new
      getter hmac_keys = Array(String).new
      property open_cmd = ""
      property close_cmd = ""
      property nftables_cmd = ""
      property nftablesv6_cmd = ""

      def initialize(@name : String)
      end

      def nftables? : Bool
        !@nftables_cmd.empty? || !@nftablesv6_cmd.empty?
      end

      def to_s(io : IO) : Nil
        io << (@name.empty? ? "default" : @name)
      end

      protected def validate!(warnings : Array(String)) : Nil
        raise Error.new("Profile '#{self}' has no key") if @keys.empty?
        raise Error.new("Profile '#{self}' has no hmac-key") if @hmac_keys.empty?
        unless @keys.all? { |k| k.hexbytes?.try(&.bytesize) == 32 }
          raise Error.new("Profile '#{self}': key must be 32 bytes hex encoded (64 characters)")
        end
        unless @hmac_keys.all? { |k| k.hexbytes?.try(&.bytesize) == 32 }
          raise Error.new("Profile '#{self}': hmac-key must be 32 bytes hex encoded (64 characters)")
        end
        if !nftables? && @open_cmd.empty?
          raise Error.new("Profile '#{self}' has no nftables-cmd, nftablesv6-cmd or open-cmd")
        end
        # with a nftables command the open/close commands are never run
        cmds = nftables? ? {"nftables-cmd" => @nftables_cmd, "nftablesv6-cmd" => @nftablesv6_cmd} : {"open-cmd" => @open_cmd, "close-cmd" => @close_cmd}
        cmds.each do |setting, cmd|
          next if cmd.empty?
          # the commands are format strings, %s is replaced with the IP
          begin
            formatted = sprintf(cmd, "192.0.2.1")
          rescue ex
            # not only ArgumentError, a huge width (%99999999999s) overflows
            raise Error.new("Profile '#{self}': #{setting} is not a valid format string, #{ex.message} (write a literal % as %%)")
          end
          warnings << "Profile '#{self}': #{setting} has no %s, the IP won't be part of the command" unless formatted.includes?("192.0.2.1")
        end
      end

      # Set a profile setting, returns false if the key isn't a profile setting
      protected def set?(key : String, value : String) : Bool
        case key
        when "key"            then @keys << value
        when "hmac-key"       then @hmac_keys << value
        when "open-cmd"       then @open_cmd = value
        when "close-cmd"      then @close_cmd = value
        when "nftables-cmd"   then @nftables_cmd = value
        when "nftablesv6-cmd" then @nftablesv6_cmd = value
        else                       return false
        end
        true
      end
    end

    getter profiles = Array(Profile).new
    getter host = "127.0.0.1"
    getter port = 8484
    getter config_file = "/etc/sparoid.ini"
    # Only verify the config file, don't start the server
    getter? check = false
    # Things in the config file that are suspicious, but not errors
    getter warnings = Array(String).new

    def initialize
      parse_options
      File.open(@config_file) { |file| parse_config(file) }
    rescue File::NotFoundError
      STDERR.puts "Config file '#{@config_file}' not found"
      exit 1
    end

    def initialize(io : IO)
      parse_config(io)
    end

    # Parse and validate a config file, raises if it's invalid
    def self.load(config_file : String) : Config
      File.open(config_file) { |file| new(file) }
    end

    private def parse_options
      OptionParser.parse do |parser|
        parser.banner = "Usage: #{PROGRAM_NAME} [arguments]"
        parser.on("-c CONFIG", "--config=CONFIG", "Path to config file (default: /etc/sparoid.ini)") { |v| @config_file = v }
        parser.on("-t", "--check", "Verify the config file and exit") { @check = true }
        parser.on("-h", "--help", "Show this help") do
          puts parser
          exit
        end
        parser.on("--version", "Show version") do
          puts Sparoid::VERSION
          exit
        end

        parser.invalid_option do |flag|
          STDERR.puts "ERROR: #{flag} is not a valid option."
          STDERR.puts parser
          exit 1
        end
      end
    end

    private def parse_config(io : IO)
      @profiles.clear
      INI.parse(io).each do |section, values|
        if section.downcase == "default"
          raise Error.new("Section [#{section}] is reserved, put the default profile's settings at the top of the file")
        end
        profile = Profile.new(section)
        has_profile_settings = false
        values.each do |k, v|
          next has_profile_settings = true if profile.set?(k, v)
          case k
          when "bind", "port"
            raise Error.new("'#{k}' is not allowed in section [#{section}], set it at the top of the file") unless section.empty?
            set_listen(k, v)
          else
            @warnings << "Unknown setting '#{k}' #{section.empty? ? "at the top of the file" : "in section [#{section}]"}, ignored"
          end
        end
        # the top level is only a profile if it has more than bind/port,
        # a partial one (eg. a command but no keys) is an error, not ignored
        next if section.empty? && !has_profile_settings
        profile.validate!(@warnings)
        @profiles << profile
      end
      raise Error.new("No keys configured") if @profiles.empty?
      validate_unique_hmac_keys!
    end

    private def set_listen(key : String, value : String) : Nil
      if key == "bind"
        raise Error.new("Invalid bind address '#{value}', it has to be an IP address") unless Socket::IPAddress.valid?(value)
        @host = value
      else
        port = value.to_i?
        raise Error.new("Invalid port '#{value}'") unless port && 0 < port < 65536
        @port = port
      end
    end

    # The profile is selected by the HMAC key
    private def validate_unique_hmac_keys! : Nil
      seen = Set(Bytes).new
      @profiles.each do |profile|
        profile.hmac_keys.each do |hmac_key|
          seen.add?(hmac_key.hexbytes) || raise Error.new("Profile '#{profile}': hmac-key is already used, each HMAC key must be unique")
        end
      end
    end
  end
end
