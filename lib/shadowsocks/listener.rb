module Shadowsocks
  class Listener < ::Shadowsocks::Connection
    attr_accessor :stage, :remote_addr, :remote_port, :addr_to_send, :cached_pieces,
                  :header_length, :connector, :config, :packer

    def receive_data data
      data_handler data
      outbound_scheduler if connector
    end

    def post_init
      @stage = 0
      @cached_pieces = []
      # puts "A client has connected..."
    end

    def unbind
      # puts "A client has left..."
      connection_cleanup
    end

    def remote
      connector
    end

    private

    def parse_data parser
      @addrtype = parser.addr_type

      if parser.mode == :unsupported
        warn "unsupported addrtype: " + @addrtype.unpack('c')[0].to_s
        connection_cleanup
      end

      @addr_len      = parser.addr_len
      @addr_to_send  = parser.addr_to_send
      @remote_addr   = parser.remote_addr
      @remote_port   = parser.remote_port
      @header_length = parser.header_length
    end

    def connection_cleanup
      connector.close_connection if connector
      self.close_connection
    end
  end
end
