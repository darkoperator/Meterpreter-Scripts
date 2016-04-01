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
      'Name'          => 'Windows Enumerate ScriptingHost Configuration',
      'Description'   => %q{
        This module enumerates the Windows Scripting Host configuration if present.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    setting_key = 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings'
    print_status("Running post module against #{sysinfo['Computer']} in session #{datastore['SESSION']}")
    settings = get_settings
    print_status('Windows Scripting Host Settings:')
    trust_pol = check_winsafer(settings)
    if trust_pol == "0"
      get_trust_pol(settings)
    end
    show_exec_error(settings)
  end

  def get_settings()
    settings_vals = registry_enumvals('HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings')
    return settings_vals
  end

  def check_winsafer(settings)
    setting_key = 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings'
    if settings.include?('UseWINSAFER')

      policy_setting = registry_getvaldata(setting_key, 'UseWINSAFER')

      if policy_setting == "1"
        print_good("\tPolicy: SRP")
      else
        print_good("\tPolicy: TrustPolicy")
      end

    end
    return policy_setting
  end

  def get_trust_pol(settings, system = true)
    if settings.include?('TrustPolicy')

      if system
        setting_key = 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings'
      else
        setting_key = 'HCU\SOFTWARE\Microsoft\Windows Script Host\Settings'
      end

      trust_policy_setting = registry_getvaldata(setting_key, 'TrustPolicy')

      if trust_policy_setting == "0"
        print_good("\tTrust Policy: Run All Scripts")
      elsif trust_policy_setting == "1"
        print_good("\tTrust Policy: Promp to Run")
      elsif trust_policy_setting == "2"
        print_good("\tTrust Policy: All Signed")
      end

    else
      print_good("\tTrust Policy: NOT SET")
    end
  end

  def show_exec_error(settings)
    setting_key = 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings'
    if settings.include?('SilentTerminate')
      policy_setting = registry_getvaldata(setting_key, 'SilentTerminate')
      if policy_setting == "0"
        print_good("\tError Message: Supress")
      else
        print_good("\tError Message: Showr")
      end
    end
  end
end
