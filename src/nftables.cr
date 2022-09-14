# Class to interact with nftables
# Not linked to libnftables, but calls out to the `nft` binary
class Nftables
  def initialize
    input, @io = IO.pipe
    nft = Process.new("nft", {"-i"}, input: input, output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
    spawn do
      nft.wait
      abort "nft exited"
    end
  end

  def run_cmd(cmd : String) : Nil
    @io.puts cmd
  end

  class Error < Exception; end
end
