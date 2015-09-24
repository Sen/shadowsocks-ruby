require 'optparse'
require 'pp'

require File.expand_path('../version', __FILE__)

module Shadowsocks
  class Cli
    include ::Shadowsocks::Table

    attr_accessor :side, :args, :config

    def initialize(options)
      @side        = options[:side]
      @config      = options[:config]

      @method_options = {
        method:   config.method,
        password: config.password
      }

      if @config.method == 'table'
        table = get_table(config.password)
        @method_options.merge!(
          encrypt_table: table[:encrypt],
          decrypt_table: table[:decrypt]
        )
      end
    end

    def run
      case side
      when :local
        EventMachine::run {
          Signal.trap("INT")  { EventMachine.stop }
          Signal.trap("TERM") { EventMachine.stop }

          puts "*** Local side is up, port:#{config.local_port}"
          puts "*** Hit Ctrl+c to stop"
          EventMachine::start_server "0.0.0.0", config.local_port, Shadowsocks::Local::LocalListener, &method(:initialize_connection)
        }
      when :server
        EventMachine::run {
          Signal.trap("INT")  { EventMachine.stop }
          Signal.trap("TERM") { EventMachine.stop }

          puts "*** Server side is up, port:#{config.server_port}"
          puts "*** Hit Ctrl+c to stop"

          EventMachine::start_server "0.0.0.0", config.server_port, Shadowsocks::Server::ServerListener, &method(:initialize_connection)
        }
      end
    end

    private

    def initialize_connection connection
      connection.config                  = @config
      connection.crypto                  = Shadowsocks::Crypto.new @method_options
      connection.pending_connect_timeout = @config.timeout
      connection.comm_inactivity_timeout = @config.timeout
      connection.package                 = Shadowsocks::Package.new(password: @config.password)
    end
  end
end
