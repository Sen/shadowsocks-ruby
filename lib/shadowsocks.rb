require 'eventmachine'

module Shadowsocks
  autoload :Crypto,     'shadowsocks/crypto'
  autoload :Connection, 'shadowsocks/connection'
  autoload :Server,     'shadowsocks/server'
  autoload :Local,      'shadowsocks/local'
  autoload :Table,      'shadowsocks/table'
  autoload :Tunnel,     'shadowsocks/tunnel'
  autoload :Listener,   'shadowsocks/listener'
  autoload :Package,    'shadowsocks/package'

  module Parser
    autoload :Base,     'shadowsocks/parser/base'
    autoload :Local,    'shadowsocks/parser/local'
    autoload :Server,   'shadowsocks/parser/server'
  end
end
