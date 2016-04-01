##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  SYSMON_HASHCODE = {
    1 => 'SHA1',
    2 => 'MD5',
    3 => 'SHA256',
    4 => 'IMPHASH',
    2147483651 => 'SHA1,MD5',
    2147483653 => 'SHA1,SHA256',
    2147483654 => 'SHA256,MD5',
    2147483655 => 'SHA1,MD5,SHA256',
    2147483657 => 'SHA1,IMPHASH',
    2147483658 => 'MD5,IMPHASH',
    2147483659 => 'SHA1,MD5,IMPHASH',
    2147483660 => 'SHA256,IMPHASH',
    2147483661 => 'SHA1,SHA256,IMPHASH',
    2147483662 => 'MD5,SHA256,IMPHASH',
    2147483663 => 'SHA1,MD5,SHA256,IMPHASH',
    2147483667 => 'SHA1,MD5',
    2147483671 => 'SHA1,MD5,SHA256',
    2147483673 => 'SHA1,IMPHASH',
    2147483674 => 'MD5,IMPHASH',
    2147483675 => 'SHA1,MD5,IMPHASH',
    2147483676 => 'SHA256,IMPHASH',
    2147483677 => 'SHA1,SHA256,IMPHASH',
    2147483678 => 'MD5,SHA256,IMPHASH',
    2147483679 => 'SHA1,MD5,SHA256,IMPHASH',
  }

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Enumerate Sysinternals Sysmon Configuration',
      'Description'   => %q{
        This module enumerates Sysinternals Sysmon Configuration configuration if present.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module against #{sysinfo['Computer']} in session #{datastore['SESSION']}")
    print_status("Checking if Sysmon is installed.")
    if check_sysmon_presence
      print_good("\tSysmon.exe installed on host.")
      if check_driver
        print_good("\tSysmonDrv installed on host.")
        print_status('Sysmon settings:')
        get_settings
      end
    end
  end

  def check_sysmon_presence
    present = false
    windir = session.sys.config.getenv('windir')
    present = session.fs.file.exists?("#{windir}\\Sysmon.exe")
    return present
  end

  def check_driver
    present = false
    srvvals = registry_enumkeys('HKLM\SYSTEM\CurrentControlSet\Services')
    if srvvals and  srvvals.include?("SysmonDrv")
      present = true
    end
    return present
  end

  def get_settings
    param_key = 'HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters'
    srvvals = registry_enumvals(param_key)
    if srvvals.include?('HashingAlgorithm')
      hash_algo = registry_getvaldata(param_key,'HashingAlgorithm')
      print_good("\tHashingAlgorithm: #{SYSMON_HASHCODE[hash_algo]}")
    else
      print_good("\tHashingAlgorithm: SHA1")
    end

    if srvvals.include?('Options')
      log_options = registry_getvaldata(param_key,'Options')
      if log_options == 1
        print_good("\tNetwork connection: enabled")
        print_good("\tImage loading: disabled")
      elsif log_options == 2
        print_good("\tNetwork connection: disabled")
        print_good("\tImage loading: enabled")
      elsif log_options == 3
        print_good("\tNetwork connection: enabled")
        print_good("\tImage loading: enabled")
      end
    else
      print_good("\tNetwork connection: disabled")
      print_good("\tImage loading: disabled")
    end
    if srvvals.include?('Rules')
      print_good("\tRules: present")
    else
      print_good("\tRules: not present")
    end
  end
end
