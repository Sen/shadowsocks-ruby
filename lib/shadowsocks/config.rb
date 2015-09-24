require 'json'

module Shadowsocks
  class Config
    attr_reader :args, :server, :server_port, :local_port, :password, :timeout, :method, :config_path

    def initialize(_args)
      @args = _args || []

      parse_args
      read_config
    end

    def read_config
      @config_path = File.expand_path('../..', File.dirname(__FILE__)) + '/config.json' unless @config_path
      cfg_file = File.open @config_path
      json = JSON.parse cfg_file.read
      cfg_file.close

      @server       = json["server"]           if @server.nil?
      @password     = json["password"]         if @password.nil?
      @server_port  = json["server_port"].to_i if @server_port.nil?
      @local_port   = json["local_port"].to_i  if @local_port.nil?
      @timeout      = json["timeout"].to_i     if @timeout.nil?
      @method       = json["method"]           if @method.nil?
    end

    private

    def parse_args
      opt_parser = OptionParser.new do |opts|
        opts.banner = "Usage: ss-server [options]"

        opts.separator ""
        opts.separator "Specific options:"

        opts.on("-s", "--server ADDR", "Remote server, IP address or domain")                        { |c| @server      = c }
        opts.on("-k", "--password PASSWORD", "Password, should be same in client and server sides")  { |c| @password    = c }
        opts.on("-c", "--config PATH", "config.json path")                                           { |c| @config_path = c }
        opts.on("-p", "--port PORT", Integer, "Remote server port")                                  { |c| @server_port = c }
        opts.on("-l", "--local_port PORT", Integer, "Local client port")                             { |c| @local_port  = c }
        opts.on("-m", "--method METHOD", "Encryption method")                                        { |c| @method      = c }
        opts.on("-t", "--timeout NUMBER", Integer, "connection timeout")                             { |c| @timeout     = c }

        opts.on_tail("-v", "--version", "Show shadowsocks gem version")                              { puts Shadowsocks::VERSION; exit }
        opts.on_tail("-h", "--help", "Show this message")                                            { puts opts; exit }
      end

      opt_parser.parse!(args)
    end
  end
end
