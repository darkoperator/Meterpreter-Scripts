# encoding: UTF-8

require 'rex'
require 'msf/core'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Registry
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

    register_options([
      OptString.new('DOMAIN_DN', [false, 'DN of the domain to enumerate.', nil]),
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
      OptInt.new('MAX_SEARCH', [false, 'Maximum values to retrieve, 0 for all.', 100])

    ], self.class)
  end

  def run
    print_status("Running module against #{sysinfo['Computer']}")
    if load_extapi
      domain_dn = get_default_naming_context
      unless domain_dn.nil?
        unless datastore['DOMAIN_DN'].nil?
          domain_dn = datastore['DOMAIN_DN']
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
                            'operatingSystemServicePack',
                            'servicePrincipalName'
                          ]
                         )
        if query_result[:results].length > 0
          query_result[:results].each do |obj|
            # Resolve IPv4 address
            begin
              ipv4_info = session.net.resolve.resolve_host(obj[2][:value], AF_INET)
              table << [obj[0][:value], obj[1][:value], obj[2][:value], obj[3][:value],obj[4][:value],ipv4_info[:ip]]

              service_pack = obj[4][:value].gsub('Service Pack', 'SP')
              # Save found DC in the database
              report_host(
                  :host      => ipv4_info[:ip],
                  :os_name   => 'Windows',
                  :os_flavor => obj[3][:value],
                  :name      => obj[0][:value],
                  :purpose   => 'server',
                  :comments  => 'MS SQL Server',
                  :os_sp     => service_pack
              )
            rescue
              vprint_status 'Could not resolve IPv4 Address for Domain Controller'
            end

            # Resolve IPv6 address
            begin
              ipv6_info = session.net.resolve.resolve_host(obj[2][:value], AF_INET6)
              table << [obj[0][:value], obj[1][:value], obj[2][:value], obj[3][:value],obj[4][:value],ipv4_info[:ip]]

              service_pack = obj[4][:value].gsub('Service Pack', 'SP')
              # Save found DC in the database
              report_host(
                  :host      => ipv6_info[:ip],
                  :os_name   => 'Windows',
                  :os_flavor => obj[3][:value],
                  :name      => obj[0][:value],
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

  def get_dn
    dn = nil
    begin
      subkey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
      v_name = 'DCName'
      key_vals = registry_enumvals(subkey)
      if key_vals.include?(v_name)
        domain_dc = registry_getvaldata(subkey, v_name)
        # lets parse the information
        dom_info =  domain_dc.split('.')
        dn = "DC=#{dom_info[1,dom_info.length].join(',DC=')}"
      else
        print_status 'Host is not part of a domain.'
      end
    rescue
      print_error('Could not determine if the host is part of a domain.')
      return nil
    end
    dn
  end

end
