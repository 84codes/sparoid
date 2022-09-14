# Class to interact with nftables
# Not linked to libnftables, but calls out to the `nft` binary
class Nftables
  def self.run_cmd(cmd : String) : Nil
    status = Process.run("nft", {cmd}, output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
    status.success? || raise Error.new("nftables command '#{cmd}' failed")
  end

  def self.run_file(file : String) : Nil
    status = Process.run("nft", {"-f", file}, output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
    status.success? || raise Error.new("nftables file '#{file}' failed")
  end

  class Error < Exception; end
end
