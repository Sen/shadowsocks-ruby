require 'eventmachine'

module Shadowsocks
  autoload :Crypto,     'shadowsocks/crypto'
  autoload :Connection, 'shadowsocks/connection'
  autoload :Server,     'shadowsocks/server'
  autoload :Local,      'shadowsocks/local'
  autoload :Tunnel,     'shadowsocks/tunnel'
  autoload :Listener,   'shadowsocks/listener'
  autoload :Packer,     'shadowsocks/packer'

  module Parser
    autoload :Base,     'shadowsocks/parser/base'
    autoload :Local,    'shadowsocks/parser/local'
    autoload :Server,   'shadowsocks/parser/server'
  end
end
