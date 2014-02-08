module Bitcoin::Protocol

  class MerkleBlock < Block

    attr_accessor :hashes, :flags

    def initialize data = nil
      @tx, @hashes, @flags = [], [], []
      return  unless data
      data = StringIO.new(data)  unless data.is_a?(StringIO)
      buf = parse_data_from_io(data, true)
      hash_count = Bitcoin::P::unpack_var_int_from_io(buf)
      hash_count.times { @hashes << buf.read(32) }
      flag_count = Bitcoin::P::unpack_var_int_from_io(buf)
      @flags = buf.read(flag_count).unpack("C*")
    end


    def to_payload
      payload = super()
      payload += [@tx_count || tx.count].pack("V")
      payload += Bitcoin::P.pack_var_int(@hashes.size)
      payload += @hashes.join
      payload += Bitcoin::P.pack_var_int(@flags.size)
      payload += @flags.pack("C*")
      payload
    end

    def self.from_block blk
      b = new blk.to_payload
      b.tx = blk.tx
      b.hashes = blk.tx.map(&:hash)
      # TODO: flags
      b
    end

  end
 
  class StoredMerkleBlock < MerkleBlock

    attr_accessor :depth, :chain, :work

    def initialize data = nil
      # @depth = Bitcoin::P::unpack_var_int(data)
      # @chain = Bitcoin::P::unpack_var_int(data)
      # @work = Bitcoin::P::unpack_var_int(data)
      data = super(data)
      # @depth, @chain, @work = *(data.to_s[0..2].split("").map(&:to_i))#.unpack("VVV")
    end

    def to_payload
      # payload  = Bitcoin::P::pack_var_int(@depth)
      # payload += Bitcoin::P::pack_var_int(@chain)
      # payload += Bitcoin::P::pack_var_int(@work)
      payload = super()

      # payload += [@depth, @chain, @work].map(&:to_s).join#pack("VVV")

      payload
    end

    def self.from_block blk, depth, chain, work
      b = super(blk)
      b.depth, b.chain, b.work = depth, chain, work
      b
    end

  end


end
