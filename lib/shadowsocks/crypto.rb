require 'securerandom'
require 'openssl'
require 'digest'
require 'rbnacl'

module Shadowsocks
  class Crypto
    attr_accessor :password, :method, :cipher, :bytes_to_key_results, :iv_sent

    def initialize(options = {})
      @password = options[:password]
      @method   = options[:method].downcase
      if method_supported.nil?
        raise "Encrypt method not support"
      end

      case method
      when 'chacha20-poly1305'
        @cipher = get_chacha20_cipher()
      else
        if method != 'none'
          @cipher = get_cipher(1, SecureRandom.hex(32))
        end
      end
    end

    def method_supported
      # key len, iv len
      case method
      # when 'aes-256-gcm'       then [16, 12]
      when 'chacha20-poly1305' then [32, 12]
      when 'aes-256-cfb'       then [32, 16]
      when 'aes-128-cfb'       then [16, 16]
      when 'none'              then [0,  0]
      end
    end
    alias_method :get_cipher_len, :method_supported

    def need_hmac?
      !(/chacha|gcm/ =~ method)
    end

    def aead_encrypt?
      /chacha|gcm/ =~ method
    end

    def encrypt buf
      return buf if buf.length == 0 or method == 'none'

      case method
      when 'chacha20-poly1305'
        chacha20_encrypt(buf)
      else
        normal_encrypt(buf)
      end
    end

    def decrypt buf
      return buf if buf.length == 0 or method == 'none'

      case method
      when 'chacha20-poly1305'
        chacha20_decrypt(buf)
      else
        normal_decrypt(buf)
      end
    end

    def normal_encrypt(buf)
      if iv_sent
        @cipher.update(buf)
      else
        @iv_sent = true
        @cipher_iv + @cipher.update(buf)
      end
    end

    def normal_decrypt(buf)
      if @decipher.nil?
        decipher_iv_len = get_cipher_len[1]
        decipher_iv     = buf[0..decipher_iv_len ]
        @iv             = decipher_iv
        @decipher       = get_cipher(0, @iv)
        buf             = buf[decipher_iv_len..-1]

        return buf if buf.length == 0
      end
      @decipher.update(buf)
    end

    def chacha20_encrypt(buf)
      ad = ""

      if iv_sent
        @cipher.encrypt(@cipher_iv, buf, ad)
      else
        @iv_sent = true
        @cipher_iv + @cipher.encrypt(@cipher_iv, buf, ad)
      end
    end

    def chacha20_decrypt(buf)
      ad = ""
      if @decipher.nil?
        decipher_iv_len = get_cipher_len[1]
        decipher_iv     = buf[0..decipher_iv_len-1]
        @decrypt_iv     = decipher_iv

        @decipher       = get_chacha20_cipher()
        buf             = buf[decipher_iv_len..-1]

        return buf if buf.length == 0
      end
      @decipher.decrypt(@decrypt_iv, buf, ad)
    end

    private

    def iv_len
      @cipher_iv.length
    end

    def get_chacha20_cipher()
      m = get_cipher_len

      key, _iv   = EVP_BytesToKey(m[0], m[1])
      iv         = _iv[0..(m[1] - 1)]
      cipher     = RbNaCl::AEAD::ChaCha20Poly1305IETF.new(key)
      @cipher_iv = iv

      cipher
    end

    def get_cipher(op, iv)
      m = get_cipher_len

      key, _iv   = EVP_BytesToKey(m[0], m[1])

      iv         = _iv[0..(m[1] - 1)]
      @iv        = iv
      @cipher_iv = iv if op == 1

      cipher = OpenSSL::Cipher.new method

      op == 1 ? cipher.encrypt : cipher.decrypt

      cipher.key = key
      cipher.iv  = @iv
      cipher
    end

    def EVP_BytesToKey key_len, iv_len
      if bytes_to_key_results
        return bytes_to_key_results
      end

      m = []
      i = 0

      len = key_len + iv_len

      while m.join.length < len do
        data = if i > 0
                 m[i - 1] + password
               else
                 password
               end
        m.push Digest::MD5.digest(data)
        i += 1
      end
      ms  = m.join
      key = ms[0, key_len]
      iv  = ms[key_len, key_len + iv_len]
      @bytes_to_key_results = [key, iv]
      bytes_to_key_results
    end
  end
end
