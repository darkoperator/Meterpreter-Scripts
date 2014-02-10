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
        'Name'         => 'Windows Gather Active Directory MS SQL Servers',
        'Description'  => %Q{
          This module will enumerate MS SQL Server in the domain the host is
          a member of.
        },
        'License'       => BSD_LICENSE,
        'Author'        => 'Carlos Perez <carlos_perez[at]darkoperator.com>',
        'Platform'      => 'win',
        'SessionTypes'  => 'meterpreter'
      ))
    # Remove unneeded options
    options.remove_option('FIELDS')
    options.remove_option('DOMAIN')
    options.remove_option('FILTER')

    register_options([
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),

    ], self.class)
  end

  def run
    print_status("Running module against #{sysinfo['Computer']}")
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
            'name',
            'distinguishedname',
            'dnshostname',
            'operatingsystem',
            'operatingSystemServicePack'
          ]
        )

      domain = domain_dn

      filter = '(&(objectCategory=computer)(servicePrincipalName=MSSQLSvc*))'
      query_result = session.extapi.adsi.domain_query(
                         domain,
                         filter,
                         datastore['MAX_SEARCH'],
                         datastore['MAX_SEARCH'],
                         ['name',
                          'distinguishedname',
                          'dnshostname',
                          'operatingsystem',
                          'operatingSystemServicePack'
                        ]
                       )
      if query_result[:results].length > 0
        query_result[:results].each do |obj|
          table << obj
        end
        table.print
        print_line

        if datastore['STORE_LOOT']
          stored_path = store_loot('ad.exchange.servers', 'text/plain', session, table.to_csv)
          print_status("Results saved to: #{stored_path}")
        end

      else
        print_status("No MS SQL Servers found.")
      end
    end
  end
end
