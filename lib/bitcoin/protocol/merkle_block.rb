module Bitcoin::Protocol

  class MerkleBlock < Block

    attr_reader :block, :hashes, :flags

    attr_accessor :depth, :chain, :work

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
      payload += [@tx_count].pack("V")
      payload += Bitcoin::P.pack_var_int(@hashes.size)
      payload += @hashes.join
      payload += Bitcoin::P.pack_var_int(@flags.size)
      payload += @flags.pack("C*")
      payload
    end

  end

end
