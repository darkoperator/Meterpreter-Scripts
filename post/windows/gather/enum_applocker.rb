##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'
require 'rexml/document'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Accounts
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Enumerate AppLocker mode and rules.',
      'Description'   => %q{
        This module enumerates Windows AppLocker current mode and rules.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module against #{sysinfo['Computer']}")
    print_status('Checking if AppLocker has been configured.')
    check_service
    if check_if_applocker
      print_good("\tAppLocker configuration present.")
      rules = registry_enumkeys('HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2')
      rules.each do |r|
        process_enforcement(r)
      end
    else
      print_good("\tAppLocker has not been configured on this system.")
    end
  end

  def check_if_applocker()
    if registry_enumkeys('HKLM\SOFTWARE\Policies\Microsoft\Windows').include?('SrpV2')
      return true
    else
      return false
    end
  end

  def process_enforcement(rule_type)
    basekey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
    if registry_enumvals(basekey + '\\' + rule_type).include?('EnforcementMode')
      print_good("\t#{rule_type}: Enabled")
      mode_val = registry_getvaldata(basekey + '\\' + rule_type, 'EnforcementMode')
      if mode_val == 0
        print_good("\t  Mode: Audit")
      else
        print_good("\t  Mode: Enforce")
      end
      process_rules(rule_type)
    else
      print_good("\t#{rule_type}: Disabled")
    end
  end

  def process_rules(rule_type)
    basekey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
    rule_base = basekey + '\\' + rule_type
    rule_guids = registry_enumkeys(rule_base)
    if rule_guids.length > 0
      rule_guids.each do |g|
        rule_xml = registry_getvaldata(rule_base + "\\#{g}", 'Value')
        rule_doc =  REXML::Document.new(rule_xml).root
        print_good(" ")
        print_good("\t  Rule Type: #{rule_doc.name}")
        rule_attributes = rule_doc.attributes
        print_good("\t\tId: #{rule_attributes['Id']}")
        print_good("\t\tName: #{rule_attributes['Name']}")
        print_good("\t\tDescription: #{rule_attributes['Description']}")
        resolution = resolve_sid(rule_attributes['UserOrGroupSid'])
        print_good("\t\tAcpplies to: " )
        print_good("\t\t\tSID: #{rule_attributes['UserOrGroupSid']}")
        print_good("\t\t\tName: #{resolution[:name]}")
        print_good("\t\t\tType: #{resolution[:type]}")
        print_good("\t\t\tDomain: #{resolution[:domain]}")
        print_good("\t\tAction: #{rule_attributes['Action']}")
        print_good("\t\tConditions:")
        confitions = rule_doc.elements['Conditions']
        confitions.each do |c|
          print_good("\t\t  Condition: #{c.name}")
          c.attributes.each {|name, value| print_good("\t\t  #{name+" => "+value}") }
          c.elements.each do |cr|
            print_good("")
            print_good("\t\t  #{cr.name}")
            cr.attributes.each {|name, value| print_good("\t\t  #{name+" => "+value}") }
          end
        end
      end
    else
      print_good("\t  No rules configured")
    end
  end

  def check_service()
    service_key = 'HKLM\SYSTEM\CurrentControlSet\services\AppIDSvc'
    startup = registry_getvaldata(service_key, 'Start')
    case startup
    when 2
      print_good("\tApplication Identity Service: Automatic")
    when 3
      print_good("\tApplication Identity Service: Manual")
    when 4
      print_good("\tApplication Identity Service: Disabled")
    else
      print_good("\tApplication Identity Service: set to #{startup}")
    end
  end
end
