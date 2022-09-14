{% if flag?(:without_nftables) %}
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
{% else %}
  # Class to interact with nftables
  # All output is printed to stdout/stderr
  class Nftables
    # Execute a nft command, eg. 'list ruleset'
    def self.run_cmd(cmd : String) : Nil
      with_ctx do |ctx|
        LibNftables.nft_run_cmd_from_buffer(ctx, cmd).zero? ||
          raise Error.new("nftables command '#{cmd}' failed")
      end
    end

    # Execute a nft script in a file
    def self.run_file(file : String) : Nil
      with_ctx do |ctx|
        LibNftables.nft_run_cmd_from_filename(ctx, file).zero? ||
          raise Error.new("nftables file '#{file}' failed")
      end
    end

    private def self.with_ctx
      ctx = LibNftables.nft_ctx_new(LibNftables::NFT_CTX_DEFAULT)
      yield ctx
    ensure
      LibNftables.nft_ctx_free(ctx) if ctx
    end

    class Error < Exception; end
  end

  # https://git.netfilter.org/nftables/plain/doc/libnftables.adoc
  # https://git.netfilter.org/nftables/tree/include/nftables/libnftables.h
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
