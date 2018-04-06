module Shadowsocks
  class Connection < EventMachine::Connection
    BackpressureLevel = 524288 # 512k

    attr_accessor :crypto

    private

    def over_pressure?
      remote.get_outbound_data_size > BackpressureLevel
    end

    def outbound_scheduler
      if over_pressure?
        pause unless paused?
        EM.add_timer(0.2) { outbound_scheduler }
      else
        resume if paused?
      end
    end
  end
end
