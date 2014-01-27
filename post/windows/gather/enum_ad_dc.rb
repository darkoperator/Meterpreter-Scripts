require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::ExtAPI

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather AD Enumerate Domain Controllers',
        'Description'   => %q{ This Module will perform an ADSI query and enumerate all Domain Controllers
          on the domain the host is a member of through a Windows Meterpreter Session.},
        'License'       => BSD_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter']
      ))
    register_options(
      [
        OptBool.new('EXCLUDE_RODC', [true, 'Exclude Read-Only Domain Controllers.', false]),
        OptInt.new('MAX_SEARCH', [false, 'Maximum values to retrieve, 0 for all.', 100])
      ], self.class)
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")

    # Make sure the extension is loaded.
    if load_extapi
      domain = get_domain
      if (!domain.nil?)

        table = Rex::Ui::Text::Table.new(
          'Indent' => 4,
          'SortIndex' => -1,
          'Columns' =>
          [
            'Hostname',
            'Addess',
            'OS',
            'SP'
          ]
        )

        inner_filter = "(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)"
        if datastore['EXCLUDE_RODC']
          inner_filter = "#{inner_filter}(!(userAccountControl:1.2.840.113556.1.4.803:=67108864))"
        end
        filter =  "(&#{inner_filter})"
        query_result = session.extapi.adsi.domain_query(domain,
                                                        filter,
                                                        datastore['MAX_SEARCH'],
                                                        datastore['MAX_SEARCH'],
                                                        ["dnshostname","operatingsystem","operatingSystemServicePack"]
                                                      )
        query_result[:results].each do |dc|
          # Resolve IPv4 address
          begin
            ipv4_info = session.net.resolve.resolve_host(dc[0], AF_INET)
            table << [dc[0],ipv4_info[:ip],dc[1],dc[2]]

            service_pack = dc[2].gsub("Service Pack", "SP")
            # Save found DC in the database
            report_host({:host => ipv4_info[:ip],
              :os_name => 'Windows',
              :os_flavor => dc[1],
              :name => dc[0],
              :purpose => 'server',
              :comments => 'Domain Controller',
              :os_sp => service_pack
            })
          rescue
          end

          # Resolve IPv6 address
          begin
            ipv6_info = session.net.resolve.resolve_host(dc[0], AF_INET6)
            table << [dc[0],ipv6_info[:ip],dc[1],dc[2]]

            # Save found DC in the database
            report_host({:host => ipv6_info[:ip],
              :os_name => 'Windows',
              :os_flavor => dc[1],
              :name => dc[0],
              :purpose => 'server',
              :comments => 'Domain Controller',
            })
          rescue
          end
        end

        table.print
        print_line("")
      end
    end
  end

  def get_domain()
    domain = nil
    begin
      subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
      v_name = "DCName"
      domain_dc = registry_getvaldata(subkey, v_name)
    rescue
      print_error("Could not determine if the host is part of a domain.")
      return nil
    end
    if (!domain_dc.nil?)
      # lets parse the information
      dom_info =  domain_dc.split('.')
      domain = dom_info[1].upcase
    else
      print_status "Host is not part of a domain."
    end
    return domain
  end
end