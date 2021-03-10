require "option_parser"
require "ini"

class Config
  getter key = "000000000000000000000000000000000000000000000000000000000000000000"
  getter hmac_key = "000000000000000000000000000000000000000000000000000000000000000000"
  getter host = "0.0.0.0"
  getter port = 8484
  getter open_cmd = ""
  getter close_cmd = ""
  @config_path : String? = nil

  def initialize
    default_cmds
    parse_options
    parse_config
  end

  private def default_cmds
    case
    when File.exists?("/usr/sbin/ufw") # ubuntu
      @open_cmd  = "ufw allow from %s to any port 22 proto tcp"
      @close_cmd = "ufw delete allow from %s to any port 22 proto tcp"
    when File.exists?("/usr/sbin/firewall-cmd") # fedora/centos
      @open_cmd = %(firewall-cmd --add-rich-rule='rule family="ipv4" source address="%s" port protocol="tcp" port="22" accept' --timeout=15)
    when File.exists?("/usr/sbin/iptables") # other linux systems
      @open_cmd = %(iptables -A INPUT -p tcp --dport 22 -s %s -j ACCEPT)
      @close_cmd = %(iptables -D INPUT -p tcp --dport 22 -s %s -j ACCEPT)
    end
  end

  private def parse_options
    OptionParser.parse do |parser|
      parser.banner = "Usage: #{PROGRAM_NAME} [arguments]"
      parser.on("-c CONFIG", "--config=CONFIG", "Path to config file") { |v| @config_path = v }
      parser.on("-k KEY", "--key=KEY", "Decryption key") { |v| @key = v }
      parser.on("-H KEY", "--hmac-key=KEY", "HMAC key") { |v| @hmac_key = v }
      parser.on("-b HOST", "--bind=HOST", "Address to listen on") { |v| @host = v }
      parser.on("-p PORT", "--port=PORT", "Port to listen on") { |v| @port = v.to_i }
      parser.on("--open-cmd CMD", "Command to open the firewall, %s will be replace with the IP") do |v|
        open_cmd = v
      end
      parser.on("--close-cmd CMD", "Command to close the firewall, %s will be replace with the IP") do |v|
        close_cmd = v
      end

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
    cp = @config_path || return
    File.open(cp) do |f|
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
    STDERR.puts "Config file '#{cp}' not found"
    exit 1
  end
end
