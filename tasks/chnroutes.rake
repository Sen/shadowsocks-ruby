require 'ipaddr'
require 'benchmark'

task :fetch_chnroutes do
  url = 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
  unless File.exists?('./delegated-apnic-latest')
    `wget -v #{url}`
  end

  lines = File.readlines './delegated-apnic-latest'
  file = File.open("./data/gfwlist.txt", "w")
  lines.each do |line|
    unit_items  = line.split('|')
    if unit_items.length >= 5 and unit_items[2] == 'ipv4' and unit_items[1] == "CN"
      starting_ip = unit_items[3]
      num_ip      = unit_items[4].to_i

      file.puts "#{starting_ip}/#{32 - (Math.log(num_ip, 2).ceil).to_i}"
    end
  end
end

task :test_ip do
  ip = '162.243.140.72'
  lines = File.readlines("./data/gfwlist.txt")
  internals = []
  lines.each do |line|
    internals << IPAddr.new(line)
  end

  Benchmark.bm do |x|
    x.report { 50.times { internals.any? { |i| i.include?(ip) } } }
  end
end

task :test_new_ip do
  ip = '122.97.254.169'
  lines = File.readlines("./data/gfwlist.txt")
  internals = {}
  nums      = []
  lines.each do |line|
    num = IPAddr.new(line).to_i
    nums << num
    internals[num.to_s] = line
  end
  nums.sort!

  Benchmark.bm do |x|
    x.report do
      1000.times do
        ip_num = IPAddr.new(ip).to_i

        i = nums.bsearch { |x| x > ip_num }
        index = nums.index(i) - 1
        IPAddr.new(internals[nums[index].to_s]).include? ip
      end
    end
  end

end
