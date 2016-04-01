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
        'Name'         => 'Windows Gather Active Directory Sites',
        'Description'  => %Q{
          This module will enumerate MS Active Directory Sites.
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
      OptString.new('DOMAIN_DN', [false, 'DN of the Forest Root to enumerate.', nil]),
      #OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
      OptInt.new('MAX_SEARCH', [false, 'Maximum values to retrieve, 0 for all.', 100])

    ], self.class)
  end

  def run
    subnets = []
    print_status("Running module against #{sysinfo['Computer']}")
    if load_extapi
      domain_dn = get_dn
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
              "name", "SerialNumber", "cn"
            ]
          )

        domain = 'CN=Sites,CN=Configuration,' + domain_dn
        print_status("Enumerating the following path for Site information.")
        filter =   "(objectClass=site)"
        # Enumerate all Sites in the forest.
        print_status("Performing query for AD Sites")
        site_query_result = session.extapi.adsi.domain_query(
                           domain,
                           filter,
                           datastore['MAX_SEARCH'],
                           datastore['MAX_SEARCH'],
                           ["cn"]
                         )

        # Enumerate all subnets in the forest.
        if site_query_result[:results].length > 0
          print_status("Performing query for subnets.")
          subnet_query_result = session.extapi.adsi.domain_query(
                           domain,
                           "(objectClass=subnet)",
                           datastore['MAX_SEARCH'],
                           datastore['MAX_SEARCH'],
                           ['cn','siteObject']
                         )

          # Process each subnet in the forest and create a Hash Table with the info.
          if subnet_query_result[:results].length > 0
            subnet_query_result[:results].each do |obj|
              subnet = {}
              subnet[:name] = obj[0][:value]
              print_good("\tName: #{obj[0][:value]}")
              subnet[:site] = obj[1][:value]
              print_good("\tSite: #{obj[1][:value]}")
              subnets << subnet
              print_good('')
              puts "adding note for #{obj[0][:value]}"
              report_note(:host   => session,
                :type   => 'ad.subnet',
                :data   => { :subnet => obj[0][:value],
                             :site => obj[1][:value]},
                :update => :unique_data)
            end
          end

          #  For each site create a hash table with its information.
          site_query_result[:results].each do |obj|
            # Enumerate the servers on the site.
            print_status("Enumerating servers for site #{obj[0][:value]}")
            site_dn = "CN=Servers,CN=#{obj[0][:value]},#{domain}"
            server_query_result = session.extapi.adsi.domain_query(
                           site_dn,
                           "(objectClass=server)",
                           datastore['MAX_SEARCH'],
                           datastore['MAX_SEARCH'],
                           ['cn','dNSHostName']
                         )
            if server_query_result[:results].length > 0
              server_query_result[:results].each do |server|
                print_good("\tName: #{server[0][:value]}")
                print_good("\tFQDN: #{server[1][:value]}")
                # Resolving server to its IPv4 address
                begin
                  ipv4_info = session.net.resolve.resolve_host(server[1][:value], AF_INET)
                  print_good("\tIPv4: #{ipv4_info[:ip]}")
                  report_host(
                    :host      => ipv4_info[:ip],
                    :name      => server[0][:value],
                    :purpose   => 'server',
                    :comments  => 'Domain Controller'
                  )
                rescue
                  vprint_status("Could not resolve the IPv4 address of #{server[1][:value]}")
                end

                # Resolve IPv6 Address.
                begin
                  ipv6_info = session.net.resolve.resolve_host(server[1][:value], AF_INET6)
                  print_good("\tIPv6: #{ipv6_info[:ip]}")
                  report_host(
                    :host      => ipv6_info[:ip],
                    :name      => server[0][:value],
                    :purpose   => 'server',
                    :comments  => 'Domain Controller'
                  )
                rescue
                  vprint_status("Could not resolve the IPv6 address of #{server[1][:value]}")
                end
                print_good('')
              end
            else
              print_status("Site #{obj[0][:value]} does not have servers assigned to it.")
            end
          end
          #table.print
          #print_line

          #if datastore['STORE_LOOT']
          #  stored_path = store_loot('ad.exchange.servers', 'text/plain', session, table.to_csv)
          #  print_status("Results saved to: #{stored_path}")
          #end

        else
          print_status("No MS AD Sites configured.")
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
