module Shadowsocks
  module Server
    class RequestConnector < ::Shadowsocks::Tunnel
      def post_init
        puts "connecting #{server.remote_addr}:#{server.remote_port} via #{server.config.server}"

        server.cached_pieces.each { |piece| send_data piece }
        server.cached_pieces = nil

        server.stage = 5
      end

      def receive_data data
        server.send_data packer.pack(data)
        outbound_scheduler
      end
    end

    class ServerListener < ::Shadowsocks::Listener
      private

      def data_handler data
        datas = []
        begin
          packer.push(data)
          packer.pop.each do |i|
            datas.push packer.unpack(i)
          end
        rescue BufLenInvalid, HmacInvalid, PackerInvalid, PackerTimeout, RbNaCl::CryptoError => e
          warn e
          connection_cleanup
        end
        datas.each { |i| handle_stage(i) }
      end

      def handle_stage(data)
        case stage
        when 0
          fireup_tunnel data
        when 4
          cached_pieces.push data
        when 5
          connector.send_data(data) and return
        end
      end

      def fireup_tunnel data
        begin
          parse_data Shadowsocks::Parser::Server.new(data)

          @stage = 4

          if data.size > header_length
            cached_pieces.push data[header_length, data.size]
          end

          @connector = EM.connect @remote_addr, @remote_port, RequestConnector, self, crypto, packer
        rescue Exception => e
          warn e
          connection_cleanup
        end
      end
    end
  end
end
