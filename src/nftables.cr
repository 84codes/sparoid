@[Extern]
struct NftCtx
end

# https://git.netfilter.org/nftables/tree/include/nftables/libnftables.h
@[Link("nftables")]
lib LibNftables
  NFT_CTX_DEFAULT = 0u32
  fun nft_ctx_new(flags : UInt32) : NftCtx*
  fun nft_ctx_free(ctx : NftCtx*) : Void
  fun nft_run_cmd_from_buffer(ctx : NftCtx*, buf : LibC::Char*) : LibC::Int
  fun nft_run_cmd_from_filename(ctx : NftCtx*, buf : LibC::Char*) : LibC::Int
end

class Nftables
  def initialize
    @nft = LibNftables.nft_ctx_new(LibNftables::NFT_CTX_DEFAULT)
  end

  def finalize
    LibNftables.nft_ctx_free(@nft)
  end

  def run_cmd(cmd : String) : Nil
    buf = Bytes.new(cmd.bytesize + 1) # null terminated string
    buf.copy_from(cmd.to_slice)
    LibNftables.nft_run_cmd_from_buffer(@nft, buf).zero? ||
      raise Error.new("nftables command could not be executed")
  end

  def run_file(file : String) : Nil
    buf = Bytes.new(file.bytesize + 1) # null terminated string
    buf.copy_from(file.to_slice)
    LibNftables.nft_run_cmd_from_filename(@nft, buf).zero? ||
      raise Error.new("nftables file could not be executed")
  end

  class Error < Exception; end
end

Nftables.new.run_cmd("list ruleset")
