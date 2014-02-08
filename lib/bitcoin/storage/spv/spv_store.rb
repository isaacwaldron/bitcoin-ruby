# encoding: ascii-8bit
require 'leveldb'
require 'json'

Bitcoin.require_dependency :sequel, message:
  "Note: You will also need an adapter for your database like sqlite3, mysql2, postgresql"


module Bitcoin::Storage::Backends

  # Storage backend using Sequel to connect to arbitrary SQL databases.
  # Inherits from StoreBase and implements its interface.
  class SpvStore < StoreBase

    # sequel database connection
    attr_accessor :db

    DEFAULT_CONFIG = { mode: :full, cache_head: false }

    # create sequel store with given +config+
    def initialize config, *args
      super config, *args
      @blocks = {}
      connect
      @last_block = nil
    end

    # connect to database
    def connect
      @db = LevelDB::DB.new @config[:db]
    end

    # reset database; delete all data
    def reset
      @db.close
      `rm -rf #{@config[:db]}`
      @db = LevelDB::DB.new @config[:db]
    end

    def add_watched_address addr
      addrs = watched_addrs
      addrs << addr
      @db["watched_addrs"] = addrs.to_json
      log.info { "Added watched address #{addr}, now watching #{addrs.count}." }
    end

    def watched_addrs
      JSON.load(@db["watched_addrs"]) || []
    end

    # persist given block +blk+ to storage.
    def persist_block blk, chain, depth, prev_work = 0

      blk = Bitcoin::P::MerkleBlock.from_block(blk)

      blk.chain, blk.depth, blk.work = chain, depth, prev_work + blk.work

      # attrs = {
      #   :depth => depth,
      #   :chain => chain,

      #   :version => blk.ver,
      #   :prev_hash => blk.prev_block.hth,
      #   :mrkl_root => blk.mrkl_root.hth,
      #   :time => blk.time,
      #   :bits => blk.bits,
      #   :nonce => blk.nonce,
      #   :work => (prev_work + blk.block_work).to_s,

      #   :hashes => blk.hashes,
      #   :flags => blk.flags,
      # }

      # attrs[:aux_pow] = blk.aux_pow.to_payload.blob  if blk.aux_pow

      key = chain == 2 ? "o#{blk.hash}" : "b#{blk.hash}"
      @db[key] = attrs.to_json
      if chain == MAIN
        @head = blk
        @db["head"] = blk.hash  
        @db["d#{depth}"] = blk.hash
      end

      blk.tx.each {|tx| store_tx(tx) }

#      if !@last_block || @last_block.to_i < Time.now.to_i - 10
      # connect orphans
      @db.range("o", "p") do |hash, attrs|
        orphan = wrap_block(JSON.load(attrs))
        if orphan.prev_block.reverse.hth == blk.hash
          begin
            store_block(orphan)
          rescue SystemStackError
            EM.defer { store_block(orphan) }  if EM.reactor_running?
          end
        end
      end
#      end
      @last_block = Time.now

      return depth, chain
    end

    def reorg new_side, new_main
      new_side.each do |hash|
        attrs = JSON.load(@db["b#{hash}"])
        attrs["chain"] = 1
        @db["b#{hash}"] = attrs.to_json
      end

      new_main.each do |hash|
        attrs = JSON.load(@db["b#{hash}"])
        attrs["chain"] = 0
        @db["b#{hash}"] = attrs.to_json
        @db["d#{attrs["depth"]}"] = hash
      end

    end

    # parse script and collect address/txout mappings to index
    def parse_script txout, i, tx_hash = "", tx_idx
      addrs, names = [], []

      script = Bitcoin::Script.new(txout.pk_script) rescue nil
      if script
        if script.is_hash160? || script.is_pubkey?
          addrs << [i, script.get_hash160]
        elsif script.is_multisig?
          script.get_multisig_pubkeys.map do |pubkey|
            addrs << [i, Bitcoin.hash160(pubkey.unpack("H*")[0])]
          end
        elsif Bitcoin.namecoin? && script.is_namecoin?
          addrs << [i, script.get_hash160]
          names << [i, script]
        else
          log.info { "Unknown script type in #{tx_hash}:#{tx_idx}" }
          log.debug { script.to_string }
        end
        script_type = SCRIPT_TYPES.index(script.type)
      else
        log.error { "Error parsing script #{tx_hash}:#{tx_idx}" }
        script_type = SCRIPT_TYPES.index(:unknown)
      end
      [script_type, addrs, names]
    end

    # bulk-store addresses and txout mappings
    def persist_addrs addrs
      addr_txouts, new_addrs = [], []
      addrs.group_by {|_, a| a }.each do |hash160, txouts|
        if existing = @db[:addr][:hash160 => hash160]
          txouts.each {|id, _| addr_txouts << [existing[:id], id] }
        else
          new_addrs << [hash160, txouts.map {|id, _| id }]
        end
      end
      new_addr_ids = @db[:addr].insert_multiple(new_addrs.map {|hash160, txout_id|
        { hash160: hash160 } })
      new_addr_ids.each.with_index do |addr_id, idx|
        new_addrs[idx][1].each do |txout_id|
          addr_txouts << [addr_id, txout_id]
        end
      end
      @db[:addr_txout].insert_multiple(addr_txouts.map {|addr_id, txout_id|
        { addr_id: addr_id, txout_id: txout_id }})
    end

    # prepare transaction data for storage
    def tx_data tx
      { hash: tx.hash.htb.blob,
        version: tx.ver, lock_time: tx.lock_time,
        coinbase: tx.in.size == 1 && tx.in[0].coinbase?,
        tx_size: tx.payload.bytesize }
    end

    # store transaction +tx+
    def store_tx(tx, validate = true)
      relevant = false
      # TODO optimize
      tx.out.each.with_index {|o,i|
        script = Bitcoin::Script.new(o.pk_script)
        addresses = script.get_addresses
        relevant = true  if (addresses.map {|a| Bitcoin.hash160_from_address(a) } & watched_addrs).any?
      }
      tx.in.each {|i|
        next  unless prev_out = get_tx(i.prev_out.reverse_hth).out[i.prev_out_index]
        relevant = true  if (Bitcoin::Script.new(prev_out.pk_script).get_addresses.map {|a| Bitcoin.hash160_from_address(a) } & watched_addrs).any?
      }
      return  unless relevant
      binding.pry
      @log.debug { "Storing tx #{tx.hash} (#{tx.to_payload.bytesize} bytes)" }

      @db["t#{tx.hash}"] = tx.payload
      p :stored_tx
    end

    # check if block +blk_hash+ exists
    def has_block(blk_hash)
      !!@db["b#{blk_hash}"]
    end

    # check if transaction +tx_hash+ exists
    def has_tx(tx_hash)
      !!@db["t#{tx_hash}"]
    end

    # get head block (highest block from the MAIN chain)
    def get_head
      get_block(@db[:head]) rescue nil
    end

    def get_head_hash
      @db[:head]
    end

    # get depth of MAIN chain
    def get_depth
      get_head.depth rescue -1
    end

    # get block for given +blk_hash+
    def get_block(blk_hash)
      wrap_block(JSON.load(@db["b#{blk_hash}"]))
    end

    # get block by given +depth+
    def get_block_by_depth(depth)
      get_block(@db["d#{depth}"])
    end

    # get block by given +prev_hash+
    def get_block_by_prev_hash(prev_hash)
      get_block(@db["d#{get_block(prev_hash).depth + 1}"])
    end

    # # get block by given +tx_hash+
    # def get_block_by_tx(tx_hash)
    #   TODO
    # end

    # get transaction for given +tx_hash+
    def get_tx(tx_hash)
      wrap_tx(Bitcoin::P::Tx.new(@db["t#{tx_hash}"]))
    end

    # # get corresponding Models::TxIn for the txout in transaction
    # # +tx_hash+ with index +txout_idx+
    # def get_txin_for_txout(tx_hash, txout_idx)
    #   TODO
    # end

    # # get corresponding Models::TxOut for +txin+
    # def get_txout_for_txin(txin)
    #   TODO
    # end

    # # get all Models::TxOut matching given +script+
    # def get_txouts_for_pk_script(script)
    #   TODO
    # end

    # get all Models::TxOut matching given +hash160+
    def get_txouts_for_hash160(hash160, unconfirmed = false)
      txouts = []
      @db.range("t", "u") do |hash, attrs|
        tx = wrap_tx(Bitcoin::P::Tx.new(attrs))
        tx.out.each.with_index do |txout, idx|
          script = Bitcoin::Script.new(txout.pk_script)
          if script.get_addresses.include?(Bitcoin.hash160_to_address(hash160))
            txouts << wrap_txout(txout, tx.hash, idx, script)
          end
        end
      end
      # TODO: select confirmed
      txouts
    end

    # # Grab the position of a tx in a given block
    # def get_idx_from_tx_hash(tx_hash)
    #   TODO
    # end

    # wrap given +block+ into Models::Block
    def wrap_block(block)

      return nil  unless block

      data = { id: block["depth"], depth: block["depth"], chain: block["chain"], work: block["work"].to_i, size: block["blk_size"]}
      blk = Bitcoin::Storage::Models::Block.new(self, data)

      blk.ver = block["version"]
      blk.prev_block = block["prev_hash"].htb
      blk.mrkl_root = block["mrkl_root"].htb
      blk.time = block["time"].to_i
      blk.bits = block["bits"]
      blk.nonce = block["nonce"]

      blk.aux_pow = Bitcoin::P::AuxPow.new(block["aux_pow"])  if block["aux_pow"]

      blk.hashes = block["hashes"]
      blk.flags = block["flags"]

      blk.recalc_block_hash
      blk
    end

    # wrap given +transaction+ into Models::Transaction
    def wrap_tx(transaction, block_id = nil)
      return nil  unless transaction

      data = {id: transaction.hash, blk_id: 0, size: transaction.to_payload.bytesize, idx: 0}
      tx = Bitcoin::Storage::Models::Tx.new(self, data)

      transaction.in.map.with_index {|i, idx| tx.add_in wrap_txin(i, tx, idx) }
      transaction.out.map.with_index {|o, idx| tx.add_out wrap_txout(o, tx, idx) }

      tx.hash = tx.hash_from_payload(tx.to_payload)
      tx
    end

    # wrap given +input+ into Models::TxIn
    def wrap_txin(input, tx, idx)
      return nil  unless input
      data = { tx_id: tx.hash, tx_idx: idx }
      txin = Bitcoin::Storage::Models::TxIn.new(self, data)
      txin.prev_out = input.prev_out
      txin.prev_out_index = input.prev_out_index
      txin.script_sig_length = input.script_sig.bytesize
      txin.script_sig = input.script_sig
      txin.sequence = input.sequence
      txin
    end

    # wrap given +output+ into Models::TxOut
    def wrap_txout(output, tx, idx, script = nil)
      return nil  unless output
      script ||= Bitcoin::Script.new(output.pk_script)
      data = {
        hash160: Bitcoin.hash160_from_address(script.get_address),
        type: script.type}
      txout = Bitcoin::Storage::Models::TxOut.new(self, data)
      txout.value = output.value
      txout.pk_script = output.pk_script
      txout
    end

    def check_consistency count = 1000
    end

  end

end
