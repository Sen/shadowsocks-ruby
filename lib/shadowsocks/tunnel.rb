module Shadowsocks
  class Tunnel < ::Shadowsocks::Connection
    attr_accessor :server, :packer, :crypto

    def initialize server, crypto, packer
      @server  = server
      @crypto  = crypto
      @packer = packer
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
