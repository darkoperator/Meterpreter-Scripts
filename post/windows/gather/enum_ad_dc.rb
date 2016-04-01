# encoding: UTF-8

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::ExtAPI

  def initialize(info = {})
    super(update_info(
          info,
          'Name'          => 'Windows Gather AD Enumerate Domain Controllers',
          'Description'   => %q{ This Module will perform an ADSI query and
           enumerate all Domain Controller on the domain the host is a
           member of through a Windows Meterpreter Session.},
          'License'       => BSD_LICENSE,
          'Author'        => 'Carlos Perez <carlos_perez[at]darkoperator.com>',
          'Platform'      => 'win',
          'SessionTypes'  => 'meterpreter'
      ))
    register_options(
      [
        OptString.new('DOMAIN_DN', [false, 'DN of the domain to enumerate.', nil]),
        OptBool.new('EXCLUDE_RODC',
                    [true, 'Exclude Read-Only Domain Controllers.', false]
                   ),
        OptInt.new('MAX_SEARCH',
                   [false, 'Maximum values to retrieve, 0 for all.', 100]
                  )
      ], self.class)
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")

    # Make sure the extension is loaded.
    if load_extapi
      domain = check_domain

        unless domain.nil?

        unless datastore['DOMAIN_DN'].nil?
          domain = datastore['DOMAIN_DN']
        end
        table = Rex::Ui::Text::Table.new(
          'Indent' => 4,
          'SortIndex' => -1,
          'Columns' =>
          [
            'HostName',
            'Address',
            'OS',
            'SP'
          ]
        )

        inner_filter = '(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)'

        if datastore['EXCLUDE_RODC']
          inner_filter = "#{inner_filter}(!(userAccountControl:1.2.840.113556.1.4.803:=67108864))"
        end
        filter =  "(&#{inner_filter})"
        fields = [
          'dnshostname',
          'operatingsystem',
          'operatingSystemServicePack'
        ]
        query_result = session.extapi.adsi.domain_query(
                        domain,
                        filter,
                        datastore['MAX_SEARCH'],
                        datastore['MAX_SEARCH'],
                        fields
                      )
        if query_result[:results].empty?
          print_status 'No results where found.'
          return
        end

        query_result[:results].each do |dc|
          # Resolve IPv4 address
          begin
            ipv4_info = session.net.resolve.resolve_host(dc[0][:value], AF_INET)
            table << [dc[0][:value], ipv4_info[:ip], dc[1][:value], dc[2][:value]]

            service_pack = dc[2][:value].gsub('Service Pack', 'SP')
            # TODO: add check so as to not stomp other comments
            # host = framework.db.find_or_create_host(:host => '10.10.10.3')

            # Save found DC in the database
            report_host(
                :host      => ipv4_info[:ip],
                :os_name   => 'Windows',
                :os_flavor => dc[1][:value],
                :name      => dc[0][:value],
                :purpose   => 'server',
                :comments  => 'Domain Controller',
                :os_sp     => service_pack
            )
          rescue
            vprint_status 'Could not resolve IPv4 Address for Domain Controller'
          end

          # Resolve IPv6 address
          begin
            ipv6_info = session.net.resolve.resolve_host(dc[0][:value], AF_INET6)
            table << [dc[0][:value], ipv6_info[:ip], dc[1][:value], dc[2][:value]]

            # Save found DC in the database
            report_host(
                :host => ipv6_info[:ip],
                :os_name    => 'Windows',
                :os_flavor  => dc[1][:value],
                :name       => dc[0][:value],
                :purpose    => 'server',
                :comments   => 'Domain Controller'
            )
          rescue
            vprint_status 'Could not resolve IPv6 Address for Domain Controller'
          end
        end

        table.print
        print_line
      end
    end
  end

  def check_domain
    domain = nil
    begin
      subkey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
      v_name = 'DCName'
      key_vals = registry_enumvals(subkey)
      if key_vals.include?(v_name)
        domain_dc = registry_getvaldata(subkey, v_name)
        # lets parse the information
        dom_info =  domain_dc.split('.')
        domain = dom_info[1].upcase
      else
        print_status 'Host is not part of a domain.'
      end
    rescue
      print_error('Could not determine if the host is part of a domain.')
      return nil
    end
    domain
  end
end
