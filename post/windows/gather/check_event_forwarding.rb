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
      'Name'          => 'Windows checks if push event forwarding is configured.',
      'Description'   => %q{
        Windows checks if push event forwarding is configured
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module against #{sysinfo['Computer']}")
    print_status('Checking EventLog Forwarding push subscriptions.')
      pol_keys = registry_enumkeys('HKLM\SOFTWARE\Policies\Microsoft\Windows')
      if pol_keys.include?('EventLog')
        begin
          sub_mng_key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
          subscribers = registry_enumvals(sub_mng_key)
          if subscribers.length > 0
            print_good('EventLog Forwarding push subscriptions configured.')
            subscribers.each do |s|
              print_good("Subscriber index #{s}")
              subscriber_info = registry_getvaldata("#{sub_mng_key}", s)
              subscriber_info.split(',').each do |d|
                print_good("\t"+d)
              end
            end
          else
            print_status('No subscriptions found on the system.')
          end
        rescue
          print_status('No subscriptions found on the system.')
          return
        end
      else
        print_status('System is not configured to push EventLogs to a central server.')
      end
  end
end
