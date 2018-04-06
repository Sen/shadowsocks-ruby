require "minitest/autorun"
require_relative '../lib/shadowsocks/packer'
require_relative '../lib/shadowsocks/crypto'
require 'timecop'

#ruby -Itest test/packer_test.rb
class TestPacker < Minitest::Test
  def test_pack_with_cfb_method
    crypto = Shadowsocks::Crypto.new(password: 'kickass', method: 'aes-256-cfb')
    packer = Shadowsocks::Packer.new(password: 'kickass', crypto: crypto)
    str = 'abcdefghijklmn'

    buf = packer.pack(str)

    assert_equal packer.unpack(buf), str
  end

  def test_pack_hmac
    crypto = Shadowsocks::Crypto.new(password: 'kickass', method: 'aes-256-cfb')
    packer = Shadowsocks::Packer.new(password: 'kickass', crypto: crypto)
    str = 'abcdefghijklmn'

    buf = packer.pack_hmac(str)

    assert_equal packer.unpack_hmac(buf), str
    assert_equal buf[0..3].unpack('N')[0], buf[4..-1].length
  end

  def test_pack_timestamp
    buf     = ''
    str     = 'abcdefghijklmn'
    crypto = Shadowsocks::Crypto.new(password: 'kickass', method: 'aes-256-cfb')
    packer = Shadowsocks::Packer.new(password: 'kickass', crypto: crypto)

    Timecop.freeze(Time.now + 30) do
      buf = packer.pack_timestamp(str)
    end

    assert_equal packer.unpack_timestamp(buf), str
  end

  def test_push_and_pop
    crypto = Shadowsocks::Crypto.new(password: 'kickass', method: 'aes-256-cfb')

    packer_1 = Shadowsocks::Packer.new(password: 'kickass', crypto: crypto)
    buf_1 = packer_1.pack_hmac(packer_1.pack_timestamp('abcdefghi'))
    buf_2 = packer_1.pack_hmac(packer_1.pack_timestamp('zasdfxcvb'))

    packer_2 = Shadowsocks::Packer.new(password: 'kickass', crypto: crypto)

    packer_2.push(buf_1)
    packer_2.push(buf_2)

    assert_equal packer_2.pop, [buf_1, buf_2]
  end

  def test_harf_packer_1
    crypto = Shadowsocks::Crypto.new(password: 'kickass', method: 'aes-256-cfb')

    packer_1 = Shadowsocks::Packer.new(password: 'kickass', crypto: crypto)
    buf_1 = packer_1.pack_hmac(packer_1.pack_timestamp('abcdefghi'))
    buf_2 = packer_1.pack_hmac(packer_1.pack_timestamp('zasdfxcvb'))

    packer_2 = Shadowsocks::Packer.new(password: 'kickass', crypto: crypto)

    packer_2.push(buf_1[0..buf_1.length - 2])

    assert_equal packer_2.pop, []

    packer_2.push(buf_1[-1])
    packer_2.push(buf_2)

    assert_equal packer_2.pop, [buf_1, buf_2]
  end

  def test_harf_packer_2
    crypto = Shadowsocks::Crypto.new(password: 'kickass', method: 'aes-256-cfb')

    packer_1 = Shadowsocks::Packer.new(password: 'kickass', crypto: crypto)
    buf_1 = packer_1.pack_hmac(packer_1.pack_timestamp('abcdefghi'))
    buf_2 = packer_1.pack_hmac(packer_1.pack_timestamp('zasdfxcvb'))

    packer_2 = Shadowsocks::Packer.new(password: 'kickass', crypto: crypto)

    packer_2.push(buf_1)
    packer_2.push(buf_2[0..5])

    assert_equal packer_2.pop, [buf_1]

    packer_2.push(buf_2[6..-1])

    assert_equal packer_2.pop, [buf_2]
  end
end
