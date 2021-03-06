module Shadowsocks
  module Parser
    class Base
      attr_accessor :data, :mode

      def initialize(data)
        @data = data

        @mode = \
          case addr_type
          when "\x01"
            :ip
          when "\x03"
            :domain
          else
            :unsupported
          end
      end

      def addr_type
        raise 'Called abstract method: addr_type'
      end

      def addr_len
        raise 'Called abstract method: addr_len'
      end

      def addr_to_send
        case mode
        when :domain
          data[3..5 + addr_len + 2]
        when :ip
          data[3..9]
        end
      end

      def remote_addr
        raise 'Called abstract method: remote_addr'
      end

      def remote_port
        raise 'Called abstract method: remote_port'
      end

      def header_length
        case mode
        when :domain
          4 + addr_len
        when :ip
          7
        end
      end

      private

      def inet_ntoa n
        n.unpack("C*").join "."
      end
    end
  end
end
