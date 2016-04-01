##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows checks if Sysinternal Tools have run on the host.',
      'Description'   => %q{
        This module checks if Sysinternal Tools have run on the host..
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module against #{sysinfo['Computer']}")
    current_user = session.sys.config.getuid()
    if current_user =~ /SYSTEM/
      print_status("Running as SYSTEM, loading user registry hives for parsing.")
      hives = hives = load_missing_hives
      if hives.length > 0
        print_status("#{hives.length} are currently loaded")
        hives.each do |hive|
          user_info = resolve_sid(hive['SID'])
          print_status("Checking existence of Sysinternal Tools being used for user #{user_info[:name]}")
          check_accepteula(hive['HKU'])
        end
      end
    else
      print_status("Running as #{current_user}")
      check_accepteula("HKCU")
    end
  end

  def check_accepteula(hku_root)
    if registry_enumkeys("#{hku_root}\\Software").include?('Sysinternals')
      tool_keys = registry_enumkeys("#{hku_root}\\Software\\Sysinternals")
      print_status("The following tools have been ran:")
      tool_keys.each do |tk|
        print_good("\t#{tk}")
      end
    else
      print_status("No Sysinternal tool appears to have been ran by the user.")
    end
  end
end
