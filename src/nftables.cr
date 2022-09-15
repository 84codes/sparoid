{% if flag?(:without_nftables) %}
  # Class to interact with nftables
  # Not linked to libnftables, but calls out to the `nft` binary
  class Nftables
    def run_cmd(cmd : String) : Nil
      status = Process.run("nft", {cmd}, output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
      status.success? || raise Error.new("nftables command '#{cmd}' failed")
    end

    def run_file(file : String) : Nil
      status = Process.run("nft", {"-f", file}, output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
      status.success? || raise Error.new("nftables file '#{file}' failed")
    end

    class Error < Exception; end
  end
{% else %}
  # Class to interact with nftables
  # All output is printed to stdout/stderr
  class Nftables
    def initialize
      @nft = LibNftables.nft_ctx_new(LibNftables::NFT_CTX_DEFAULT)
    end

    def finalize
      LibNftables.nft_ctx_free(@nft)
    end

    # Execute a nft command, eg. 'list ruleset'
    def run_cmd(cmd : String) : Nil
      LibNftables.nft_run_cmd_from_buffer(@nft, cmd).zero? ||
        raise Error.new("nftables command '#{cmd}' failed")
    end

    # Execute a nft script in a file
    def run_file(file : String) : Nil
      LibNftables.nft_run_cmd_from_filename(@nft, file).zero? ||
        raise Error.new("nftables file '#{file}' failed")
    end

    class Error < Exception; end
  end

  # https://git.netfilter.org/nftables/plain/doc/libnftables.adoc
  # https://git.netfilter.org/nftables/tree/include/nftables/libnftables.h
  @[Link("mnl")]
  @[Link("nftnl")]
  @[Link("nftables")]
  lib LibNftables
    NFT_CTX_DEFAULT = 0u32
    fun nft_ctx_new(flags : UInt32) : NftCtx*
    fun nft_ctx_free(ctx : NftCtx*) : Void
    fun nft_run_cmd_from_buffer(ctx : NftCtx*, buf : LibC::Char*) : LibC::Int
    fun nft_run_cmd_from_filename(ctx : NftCtx*, buf : LibC::Char*) : LibC::Int
  end

  @[Extern]
  struct NftCtx
  end
{% end %}
