require 'openssl'
require 'zlib'

class BufLenInvalid < StandardError; end
class HmacInvalid < StandardError; end
class PackerInvalid < StandardError; end
class PackerTimeout < StandardError; end

module Shadowsocks
  class Packer
    attr_accessor :data
    attr_reader :password, :crypto

    def initialize(options = {})
      @password = options.fetch(:password)
      @crypto = options.fetch(:crypto)
    end

    def push(buf)
      @store = '' if @store.nil?
      @store += buf
    end

    def pop
      len = bytes_to_i(@store[0..3])
      if len.nil?
        []
      else
        r = []

        while !@store.nil? && !len.nil? && @store.length >= len + 4
          r.push(@store[0..3+len])

          @store = @store[4+len..-1]
          len    = bytes_to_i(@store[0..3]) unless @store.nil?
        end
        r
      end
    end

    def pack(buf)
      if crypto.need_hmac?
        prepend_pack_len(pack_hmac(encrypt(pack_timestamp(buf))))
      else
        prepend_pack_len(encrypt(pack_timestamp(buf)))
      end
    end

    def unpack(buf)
      if crypto.need_hmac?
        unpack_timestamp(decrypt(unpack_hmac(remove_pack_len(buf))))
      else
        unpack_timestamp(decrypt(remove_pack_len(buf)))
      end
    end

    def encrypt(buf)
      crypto.encrypt(buf)
    end

    def decrypt(buf)
      crypto.decrypt(buf)
    end

    def pack_timestamp(buf)
      rand_len = rand(1..255)
      rand_str  = ''

      1.upto(rand_len).each do
        rand_str += rand(0..255).chr
      end

      buf_len   = i_to_bytes(buf.length)
      timestamp = i_to_bytes(Time.now.to_i)

      rand_len.chr + rand_str + buf_len + buf + timestamp
    end

    def unpack_timestamp(buf)
      rand_len  = buf[0].ord
      buf_len   = bytes_to_i(buf[rand_len + 1..rand_len + 4])
      real_buf  = buf[rand_len + 5..rand_len + 4 + buf_len]

      timestamp = buf[rand_len + 5 + buf_len..rand_len + 8 + buf_len]

      raise PackerTimeout if Time.at(bytes_to_i(timestamp)) < (Time.now - 3600)

      real_buf
    end

    def pack_hmac(buf)
      digest   = OpenSSL::Digest.new('sha256')
      hmac     = OpenSSL::HMAC.hexdigest(digest, password, buf)
      hmac_len = i_to_bytes(hmac.length)

      buf_len  = i_to_bytes(buf.length)
      data     = buf_len + buf + hmac_len + hmac

      i_to_bytes(data.length) + data
    end

    # packer length + buf length + buf + hmac length + hmac
    def unpack_hmac(buf)
      pack_len = bytes_to_i(buf[0..3])

      raise BufLenInvalid if pack_len != buf[4..-1].length

      buf_len  = bytes_to_i(buf[4..7])
      real_buf = buf[8..8 + buf_len - 1]

      hmac_len = bytes_to_i(buf[8 + buf_len..11+buf_len])
      hmac     = buf[12 + buf_len..-1]

      raise PackerInvalid if hmac_len != hmac.length

      digest        = OpenSSL::Digest.new('sha256')
      real_buf_hmac = OpenSSL::HMAC.hexdigest(digest, password, real_buf)

      raise HmacInvalid if real_buf_hmac != hmac

      real_buf
    end

    def prepend_pack_len(buf)
      i_to_bytes(buf.length) + buf
    end

    def remove_pack_len(buf)
      buf_len = bytes_to_i(buf[0..3])
      raise BufLenInvalid if buf_len != buf[4..-1].length

      buf[4..-1]
    end

    private

    def i_to_bytes(i)
      [i].pack('N')
    end

    def bytes_to_i(bytes)
      bytes.unpack('N')[0]
    end
  end
end
