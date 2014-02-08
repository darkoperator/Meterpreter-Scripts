##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'

class Metasploit3 < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP
  include Msf::Post::Windows::ExtAPI

  def initialize(info = {})
    super( update_info(
        info,
        'Name'         => 'Windows Gather Active Directory MS Exchange Servers',
        'Description'  => %Q{
          This module will enumerate MS Exchange Server in the domain the host is
          a member of. Enumeration can be filtered by role.
        },
        'License'       => BSD_LICENSE,
        'Author'        => 'Carlos Perez <carlos_perez[at]darkoperator.com>',
        'Platform'      => 'win',
        'SessionTypes'  => 'meterpreter'
      ))
    options.remove_option('FIELDS')
    options.remove_option('DOMAIN')
    options.remove_option('FILTER')

    register_options([
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
      OptEnum.new('ROLE', [true,
                            'Filter on MS Exchange Server Role.',
                            'ANY', [
                                      'ANY',
                                      'MAIBOX',
                                      'CAS',
                                      'UNIFIED',
                                      'HUB',
                                      'EDGE']]),

    ], self.class)
  end

  def run
    if load_extapi
      begin
        domain_dn = get_default_naming_context
      rescue
        print_error('This host appears to not be part of a domain.')
        return
      end

      table = Rex::Ui::Text::Table.new(
          'Indent' => 4,
          'SortIndex' => -1,
          'Width' => 80,
          'Columns' =>
          [
            "name", "SerialNumber", "cn"
          ]
        )

      domain = 'CN=Microsoft Exchange,CN=Services,CN=Configuration,' + domain_dn

      inner_filter = '(objectCategory=msExchExchangeServer)'
      case datastore['ROLE']

      when 'ANY'
        role = 'any role'
        inner_filter = "#{inner_filter}"

      when 'MAILBOX'
        role = 'Mailbox Server Role'
        inner_filter = "(#{inner_filter}((msExchCurrentServerRoles:1.2.840.113556.1.4.803:=2)"

      when 'CAS'
        role = 'Client Access Role'
        inner_filter = "(#{inner_filter})(msExchCurrentServerRoles:1.2.840.113556.1.4.803:=4)"

      when 'UNIFIED'
        role = 'Unified Messaging Role'
        inner_filter = "(#{inner_filter})(msExchCurrentServerRoles:1.2.840.113556.1.4.803:=16)"

      when 'HUB'
        role = 'Hub Transport Role'
        inner_filter = "(#{inner_filter})(msExchCurrentServerRoles:1.2.840.113556.1.4.803:=32)"

      when 'EDGE'
        role = 'Edge Transport Role'
        inner_filter = "(#{inner_filter})(msExchCurrentServerRoles:1.2.840.113556.1.4.803:=64)"
      end

      filter =   "(&#{inner_filter})"
      print_status("Performing query for MS Exchange server with #{role}")
      query_result = session.extapi.adsi.domain_query(
                         domain,
                         filter,
                         datastore['MAX_SEARCH'],
                         datastore['MAX_SEARCH'],
                         ["name", "SerialNumber", "cn"]
                       )
      if query_result[:results].length > 0
        query_result[:results].each do |obj|
          table << obj
        end
        table.print
        print_line
      else
        print_status("No MS Exchange entries with #{role} found.")
      end
    end
  end
end
