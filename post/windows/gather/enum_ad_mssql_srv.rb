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
            'Name',
            'Distinguished Name',
            'FQDN',
            'Operating System',
            'Service Pack',
            'Address'
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
          # Resolve IPv4 address
          begin
            ipv4_info = session.net.resolve.resolve_host(obj[2], AF_INET)
            table << [obj[0], obj[1], obj[2], obj[3],obj[4],ipv4_info[:ip]]

            service_pack = obj[4].gsub('Service Pack', 'SP')
            # Save found DC in the database
            report_host(
                :host      => ipv4_info[:ip],
                :os_name   => 'Windows',
                :os_flavor => obj[3],
                :name      => obj[0],
                :purpose   => 'server',
                :comments  => 'MS SQL Server',
                :os_sp     => service_pack
            )
          rescue
            vprint_status 'Could not resolve IPv4 Address for Domain Controller'
          end

          # Resolve IPv6 address
          begin
            ipv6_info = session.net.resolve.resolve_host(obj[2], AF_INET6)
            table << [obj[0], obj[1], obj[2], obj[3],obj[4],ipv4_info[:ip]]

            service_pack = obj[4].gsub('Service Pack', 'SP')
            # Save found DC in the database
            report_host(
                :host      => ipv6_info[:ip],
                :os_name   => 'Windows',
                :os_flavor => obj[3],
                :name      => obj[0],
                :purpose   => 'server',
                :comments  => 'MS SQL Server',
                :os_sp     => service_pack
            )
          rescue
            vprint_status 'Could not resolve IPv6 Address for Domain Controller'
          end
        end
        table.print
        print_line

        if datastore['STORE_LOOT']
          stored_path = store_loot('ad.mssql.servers', 'text/plain', session, table.to_csv)
          print_status("Results saved to: #{stored_path}")
        end

      else
        print_status("No MS SQL Servers found.")
      end
    end
  end
end
