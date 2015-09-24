module Shadowsocks
  class Tunnel < ::Shadowsocks::Connection
    attr_accessor :server, :package

    def initialize server, crypto, package
      @server  = server
      @crypto  = crypto
      @package = package
      super
    end

    def unbind
      server.close_connection_after_writing
    end

    def remote
      server
    end
  end
end
