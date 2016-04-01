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
      'Name'          => 'Windows enumerate Windows Defender exclusions.',
      'Description'   => %q{
        Windows enumerate Windows Defender exclusions.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module against #{sysinfo['Computer']}")
    print_status("Enumerating Windows Defender exceptions:")
    exclusion_key = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions"
    if sysinfo['Architecture'] =~ /x64/
      exception_types = registry_enumkeys(exclusion_key,REGISTRY_VIEW_64_BIT)
    else
      exception_types = registry_enumkeys(exclusion_key)
    end
    exception_types.each do |et|
      vprint_status("Checking for #{et} exceptions.")
      if sysinfo['Architecture'] =~ /x64/
        exclusions = registry_enumvals("#{exclusion_key}\\#{et}",REGISTRY_VIEW_64_BIT)
      else
        exclusions = registry_enumvals("#{exclusion_key}\\#{et}")
      end

      if exclusions.length > 0
        print_status("Exceptions found for #{et}")
        exclusions.each do |exc|
          print_good("\t#{exc}")
        end
      else
        vprint_status("No exclusions found for #{et}")
      end
    end

  end
end
