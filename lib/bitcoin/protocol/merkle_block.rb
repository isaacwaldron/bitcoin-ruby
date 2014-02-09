module Bitcoin::Protocol

  class MerkleBlock < Block

    attr_accessor :hashes, :flags, :depth, :chain, :work

    def initialize data = nil
      @tx, @hashes, @flags = [], [], []
      return  unless data
      data = StringIO.new(data)  unless data.is_a?(StringIO)
      buf = parse_data_from_io(data, true)
      hash_count = Bitcoin::P::unpack_var_int_from_io(buf)
      hash_count.times { @hashes << buf.read(32) }
      flag_count = Bitcoin::P::unpack_var_int_from_io(buf)
      @flags = buf.read(flag_count).unpack("C*")
      buf
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
      b.hashes = blk.tx.map(&:hash).map(&:htb)
      # TODO: flags
      b
    end

    def self.from_disk data
      depth, data = Bitcoin::P::unpack_var_int(data)
      chain, data = Bitcoin::P::unpack_var_int(data)
      work, data = Bitcoin::P::unpack_var_int(data)
      b = new(data)
      b.depth, b.chain, b.work = depth, chain, work
      b
    end

    def to_disk
      Bitcoin::P.pack_var_int(@depth) +
        Bitcoin::P.pack_var_int(@chain) +
        Bitcoin::P.pack_var_int(@work) +
        to_payload
    end

  end

end
