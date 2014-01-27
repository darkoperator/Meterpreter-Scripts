require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::ExtAPI

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather AD Enumerate Domain Group Policy Objects',
        'Description'   => %q{ This Module will perform an ADSI query and enumerate all Group Policy Objects
          on the domain the host is a member of through a Windows Meterpreter Session.},
        'License'       => BSD_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter']
      ))
    register_options(
      [
        #OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
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

        #table = Rex::Ui::Text::Table.new(
        #  'Indent' => 4,
        #  'SortIndex' => -1,
        #  'Width' => 80,
        #  'Columns' =>
        #  [
        #    'Name',
        #    'DistinguishedName'
        #  ]
        #)

        wmi_filter_array = get_wmifilters(domain)

        gpo_filter =   '(objectClass=groupPolicyContainer)'
        query_result = session.extapi.adsi.domain_query(domain,
                                                        gpo_filter,
                                                        datastore['MAX_SEARCH'],
                                                        datastore['MAX_SEARCH'],
                                                        ['name',
                                                          'displayname',
                                                          'gpcfilesyspath',
                                                          'gPCWQLFilter',
                                                          'flags',
                                                          'gPCMachineExtensionNames',
                                                          'gPCUserExtensionNames']
                                                      )
        query_result[:results].each do |obj|
          print_good "Id: #{obj[0]}"
          print_good "Name: #{obj[1]}"
          print_good "Location: #{obj[2]}"
          print_good "Linked OUs: #{get_lineked_ou(domain, obj[0]).join("; ")}"

          if (obj[3].length > 0)
            print_good "WMI Filter:"
            filter_id = obj[3].split(";")[1]

            # GPO can only have on single WMI filter that can have several WQL queries
            # so the array returned will always be of one element.
            matched_filter = wmi_filter_array.select {|filter| filter[:id] == filter_id }
            print_good "\tName: #{matched_filter[0][:name]}"
            print_good "\tId: #{matched_filter[0][:id]}"
            print_good "\tWQL: #{matched_filter[0][:filter].join("; ")}"
          end

          case obj[4]
          when "0"
            print_good "Status: Enabled"

          when "1"
            print_good "Status: User Configuration settings are disabled."

          when "2"
            print_good "Status: Computer Configuration settings are disabled."

          when "3"
            print_good "Status: Disabled"
          end

          print_good "Machine Extensions: #{obj[5]}"
          print_good "USer Extensions: #{obj[6]}"
          print_line ""
        end

        #if datastore['STORE_LOOT']
        #  stored_path = store_loot('ad.groups', 'text/plain', session, table.to_csv)
        #  print_status("Results saved to: #{stored_path}")
        #end

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

  def get_wmifilters(domain)
    # Collect all WMI filters since we will need then to match found GPOs
    vprint_status("Emumerating all WMI Filters")
    wmi_filters = []
    wmi_msWMI_filter = '(objectClass=msWMI-Som)'
    wmi_fileds = ['msWMI-ID','msWMI-Name', 'msWMI-Parm2']

    msWMIquery_result = session.extapi.adsi.domain_query(domain,
                                                    wmi_msWMI_filter,
                                                    0,
                                                    0,
                                                    wmi_fileds
                                                  )

    msWMIquery_result[:results].each do |obj|
      wmi_filter = {:id => obj[0],
        :name =>  obj[1],
        :filter => obj[2].split(/;\d*;\d*;\d*;\d*WQL;/).drop(1)
      }
      wmi_filters << wmi_filter
    end
    return wmi_filters
  end

  def get_lineked_ou(domain, ou_id)

    ou_search_filter = "(&(objectclass=organizationalunit)(gplink=*#{ou_id}*))"
    linked_ous = []

    ou_query_result = session.extapi.adsi.domain_query(domain,
                                                    ou_search_filter,
                                                    0,
                                                    0,
                                                    ['distinguishedname']
                                                  )

    ou_query_result[:results].each do |obj|
      linked_ous << obj[0]
    end
    return linked_ous
  end

end