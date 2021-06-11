require "option_parser"
require "ini"

module Sparoid
  class Config
    getter key = "000000000000000000000000000000000000000000000000000000000000000000"
    getter hmac_key = "000000000000000000000000000000000000000000000000000000000000000000"
    getter host = "127.0.0.1"
    getter port = 8484
    getter open_cmd = "echo 'open %s'"
    getter close_cmd = "echo 'close %s'"
    getter config_file = "/etc/sparoid.ini"

    def initialize
      parse_options
      parse_config
    end

    private def parse_options
      OptionParser.parse do |parser|
        parser.banner = "Usage: #{PROGRAM_NAME} [arguments]"
        parser.on("-c CONFIG", "--config=CONFIG", "Path to config file (default: /etc/sparoid.ini)") { |v| @config_file = v }
        parser.on("-h", "--help", "Show this help") do
          puts parser
          exit
        end

        parser.invalid_option do |flag|
          STDERR.puts "ERROR: #{flag} is not a valid option."
          STDERR.puts parser
          exit 1
        end
      end
    end

    private def parse_config
      File.open(@config_file) do |f|
        INI.parse(f).each do |_, values|
          # ignore sections, assume there's only the empty
          values.each do |k, v|
            case k
            when "key" then @key = v
            when "hmac-key" then @hmac_key = v
            when "bind" then @host = v
            when "port" then @port = v.to_i
            when "open-cmd" then @open_cmd = v
            when "close-cmd" then @close_cmd = v
            end
          end
        end
      end
    rescue File::NotFoundError
      STDERR.puts "Config file '#{@config_file}' not found"
      exit 1
    end
  end
end
