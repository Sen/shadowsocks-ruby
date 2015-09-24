require "minitest/autorun"
require_relative '../lib/shadowsocks/package'
require 'timecop'

#ruby -Itest test/package_test.rb
class TestPackage < Minitest::Test
  def test_pack_hmac
    package = Shadowsocks::Package.new(password: 'kickass')
    str = 'abcdefghijklmn'

    buf = package.pack_hmac(str)

    assert_equal package.unpack_hmac(buf), str
    assert_equal buf[0..3].unpack('N')[0], buf[4..-1].length
  end

  def test_pack_timestamp_and_crc
    buf     = ''
    str     = 'abcdefghijklmn'
    package = Shadowsocks::Package.new(password: 'kickass')

    Timecop.freeze(Time.now + 30) do
      buf = package.pack_timestamp_and_crc(str)
    end

    assert_equal package.unpack_timestamp_and_crc(buf), str
  end

  def test_push_and_pop
    package_1 = Shadowsocks::Package.new(password: 'kickass')
    buf_1 = package_1.pack_hmac(package_1.pack_timestamp_and_crc('abcdefghi'))
    buf_2 = package_1.pack_hmac(package_1.pack_timestamp_and_crc('zasdfxcvb'))

    package_2 = Shadowsocks::Package.new(password: 'kickass')

    package_2.push(buf_1)
    package_2.push(buf_2)

    assert_equal package_2.pop, [buf_1, buf_2]
  end

  def test_harf_package_1
    package_1 = Shadowsocks::Package.new(password: 'kickass')
    buf_1 = package_1.pack_hmac(package_1.pack_timestamp_and_crc('abcdefghi'))
    buf_2 = package_1.pack_hmac(package_1.pack_timestamp_and_crc('zasdfxcvb'))

    package_2 = Shadowsocks::Package.new(password: 'kickass')

    package_2.push(buf_1[0..buf_1.length - 2])

    assert_equal package_2.pop, []

    package_2.push(buf_1[-1])
    package_2.push(buf_2)

    assert_equal package_2.pop, [buf_1, buf_2]
  end

  def test_harf_package_2
    package_1 = Shadowsocks::Package.new(password: 'kickass')
    buf_1 = package_1.pack_hmac(package_1.pack_timestamp_and_crc('abcdefghi'))
    buf_2 = package_1.pack_hmac(package_1.pack_timestamp_and_crc('zasdfxcvb'))

    package_2 = Shadowsocks::Package.new(password: 'kickass')

    package_2.push(buf_1)
    package_2.push(buf_2[0..5])

    assert_equal package_2.pop, [buf_1]

    package_2.push(buf_2[6..-1])

    assert_equal package_2.pop, [buf_2]
  end
end
