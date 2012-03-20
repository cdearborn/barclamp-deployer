# Copyright 2011, Dell
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'timeout'

provides "crowbar_ohai"

class System
  def self.background_time_command(timeout, background, name, command)
    File.open("/tmp/tcpdump-#{name}.sh", "w+") { |fd|
      fd.puts("#!/bin/bash")
      fd.puts("#{command} &")
      fd.puts("sleep #{timeout}")
      fd.puts("kill %1")
    }

    system("chmod +x /tmp/tcpdump-#{name}.sh")
    if background
      system("/tmp/tcpdump-#{name}.sh &")
    else
      system("/tmp/tcpdump-#{name}.sh")
    end
  end
end

crowbar_ohai Mash.new
crowbar_ohai[:switch_config] = Mash.new unless crowbar_ohai[:switch_config]

networks = []
mac_map = {}
bus_found=false
logical_name=""
mac_addr=""
wait=false
Dir.foreach("/sys/class/net") do |entry|
  next if entry =~ /\./
  next if entry =~ /br/
  type = File::open("/sys/class/net/#{entry}/type").readline.strip rescue "0"
  if type == "1"
    s1 = File.readlink("/sys/class/net/#{entry}") rescue ""
    spath = File.readlink("/sys/class/net/#{entry}/device") rescue "Unknown"
    spath = s1 if s1 =~ /pci/
    spath = spath.gsub(/.*pci/, "").gsub(/\/net\/.*/, "")

    crowbar_ohai[:detected] = Mash.new unless crowbar_ohai[:detected]
    crowbar_ohai[:detected][:network] = Mash.new unless crowbar_ohai[:detected][:network]
    crowbar_ohai[:detected][:network][entry] = spath

    logical_name = entry
    networks << logical_name
    f = File.open("/sys/class/net/#{entry}/address", "r")
    mac_addr = f.gets()
    mac_map[logical_name] = mac_addr.strip
    f.close
    if !File.exists?("/tmp/tcpdump.#{logical_name}.out")
      System.background_time_command(45, true, logical_name, "ifconfig #{logical_name} up ; /opt/tcpdump/tcpdump -c 1 -lv -v -i #{logical_name} -a -e -s 1514 ether proto 0x88cc > /tmp/tcpdump.#{logical_name}.out")
      wait=true
    end
  end
end
system("sleep 45") if wait

networks.each do |network|
  sw_port = -1
  line = %x[cat /tmp/tcpdump.#{network}.out | grep "Subtype Interface Name"]
  if line =~ /[\d]+\/[\d]+\/([\d]+)/
    sw_port = $1
  end
  if line =~ /: Unit [\d]+ Port ([\d]+)/
    sw_port = $1
  end

  sw_unit = -1
  line = %x[cat /tmp/tcpdump.#{network}.out | grep "Subtype Interface Name"]
  if line =~ /([\d]+)\/[\d]+\/[\d]+/
    sw_unit = $1
  end
  if line =~ /: Unit ([\d]+) Port [\d]+/
    sw_unit = $1
  end

  sw_name = -1
  # Using mac for now, but should change to something else later.
  line = %x[cat /tmp/tcpdump.#{network}.out | grep "Subtype MAC address"]
  if line =~ /: (.*) \(oui/
    sw_name = $1
  end

  crowbar_ohai[:switch_config][network] = Mash.new unless crowbar_ohai[:switch_config][network]
  crowbar_ohai[:switch_config][network][:interface] = network
  crowbar_ohai[:switch_config][network][:mac] = mac_map[network].downcase
  crowbar_ohai[:switch_config][network][:switch_name] = sw_name
  crowbar_ohai[:switch_config][network][:switch_port] = sw_port
  crowbar_ohai[:switch_config][network][:switch_unit] = sw_unit

end


# Find the vendor ID, device ID, and driver type for the controller for each
# drive
crowbar_ohai[:disk_config] = Mash.new unless crowbar_ohai[:disk_config]

# Disk device names are either sd* or hd*
file_prefixes = [ 'sd*', 'hd*' ];

file_prefixes.each do |file_prefix|
  Dir["/sys/block/" + file_prefix].each do |drive_dir|
    drive_name = File.basename( drive_dir )

    # Is this drive removable?
    removable = IO.read( drive_dir + "/removable" ).chomp

    # Skip it if so
    next if removable == 1 or removable == "1"

    # Different versions of udev change where they symlink to the device, so be a little
    # flexible
    drive_device_dir=""
    if File.symlink? drive_dir
      drive_device_dir = File.readlink( drive_dir );
    else
      # Assume that drive_dir/device is the symlink
      drive_device_dir = File.readlink( drive_dir + "/device" );
    end

    # Get the directory to the controller
    controller_dir = "/sys/" + drive_device_dir.match( "/(devices/pci.*?/.*?)/.*" )[1]

    # Read in the vendor and device IDs for the controller
    vendor_id = IO.read( controller_dir + "/vendor" ).chomp.upcase
    device_id = IO.read( controller_dir + "/device" ).chomp.upcase

    # The driver file is missing on RHEL 6 for the front drives controller
    driver_type=""
    if File.symlink?( controller_dir + "/driver" )
        driver_path = File.readlink( controller_dir + "/driver" )
        driver_type = File.basename( driver_path ).upcase
    end

    crowbar_ohai[:disk_config][drive_name] = Mash.new
    crowbar_ohai[:disk_config][drive_name][:vendor_id] = vendor_id
    crowbar_ohai[:disk_config][drive_name][:device_id] = device_id
    crowbar_ohai[:disk_config][drive_name][:driver_type] = driver_type
  end
end
