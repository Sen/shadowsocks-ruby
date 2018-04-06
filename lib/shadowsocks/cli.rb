require 'optparse'
require 'pp'

require File.expand_path('../version', __FILE__)

module Shadowsocks
  class Cli
    attr_accessor :side, :args, :config

    def initialize(options)
      @side        = options[:side]
      @config      = options[:config]

      @method_options = {
        method:   config.method,
        password: config.password
      }
    end

    def run
      case side
      when :local
        EventMachine::run {
          Signal.trap("INT")  { EventMachine.stop }
          Signal.trap("TERM") { EventMachine.stop }

          puts "*** Local side is up, local port:#{config.local_port}, remote: #{config.server}:#{config.server_port}"
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
      crypto = Shadowsocks::Crypto.new @method_options

      connection.config                  = @config
      connection.crypto                  = crypto
      connection.pending_connect_timeout = @config.timeout
      connection.comm_inactivity_timeout = @config.timeout
      connection.packer                  = Shadowsocks::Packer.new(password: @config.password, crypto: crypto)
    end
  end
end
