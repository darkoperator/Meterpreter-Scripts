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

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows enumerate DeviceGuard',
      'Description'   => %q{
        Windows enumerate DeviceGuard configuration.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module against #{sysinfo['Computer']}")
    print_status("Enumerating Windows DeviceGuard:")
    if check_windows_ver
      dgkey = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"
      registry_getvaldata(dgkey, 'EnableVirtualizationBasedSecurity')
      registry_getvaldata(dgkey, 'HypervisorEnforcedCodeIntegrity')

      
      secure_boot = registry_getvaldata(dgkey, 'RequirePlatformSecurityFeatures')
      if secure_boot == 1
        print_good('Secure Boot is enabled.')
      elsif secure_boot == 1
        print_good('Secure Boot with DMA Protection is enabled')
      else
        print_good('Secure Boot is not enabled.')
      end
    else
      print_status("This version of Windows does not support DeviceGuard.")
    end

  end

  def check_windows_ver
    if sysinfo['OS'] =~ /Windows 10/
      edition = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 'ProductName')
      if edition =~ /Enterprise/
        return true
      else
        return false
      end
    else
      return false
    end
  end
end
