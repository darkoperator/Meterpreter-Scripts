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
        'Name'          => 'Windows Gather AD Enumerate Domain Group Policy Objects',
        'Description'   => %q{ This Module will perform an ADSI query and
        enumerate all Group Policy Objects on the domain the host is a
        member of through a Windows Meterpreter Session.},
        'License'       => BSD_LICENSE,
        'Author'        => 'Carlos Perez <carlos_perez[at]darkoperator.com>',
        'Platform'      => 'win',
        'SessionTypes'  => 'meterpreter'
      ))
    register_options(
      [
        OptString.new('DOMAIN_DN', [false, 'DN of the domain to enumerate.', nil]),
        OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
        OptBool.new('LINKED', [true, 'Show linked GPOs only.', true]),
        OptInt.new('MAX_SEARCH', [false, 'Maximum values to retrieve, 0 for all.', 100])
      ], self.class)
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{ sysinfo['Computer'] }")

    # Make sure the extension is loaded.
    if load_extapi
      domain = get_domain
      unless domain.nil?

        unless datastore['DOMAIN_DN'].nil?
          domain = datastore['DOMAIN_DN']
        end

        table = Rex::Ui::Text::Table.new(
          'Indent' => 4,
          'SortIndex' => -1,
          'Width' => 80,
          'Columns' =>
          [
            'Id',
            'Name',
            'Location',
            'Linked OUs',
            'Status',
            'Machine Extensions',
            'User Extensions',
            'WMI Filter Name',
            'WMI Filter ID',
            'WMI Filter Description',
            'WMI Filter WQL'
          ]
        )

        wmi_filter_array = get_wmifilters(domain)

        gpo_filter =   '(objectClass=groupPolicyContainer)'
        query_result = session.extapi.adsi.domain_query(
                         domain,
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
          linked_ous = get_lineked_to_ou(domain, obj[0][:value])
          linked_domain = get_lineked_to_domian(domain, obj[0][:value])

          # Check if only linked GPOs are desired and process.
          next if (linked_ous.length == 0 && linked_domain == 0) && datastore['LINKED']
          print_line ""
          print_good "Id: #{obj[0][:value]}"
          print_good "Name: #{obj[1][:value]}"
          print_good "Location: #{obj[2][:value]}"
          print_good "Linked To OU: #{linked_ous.join("; ")}"
          print_good "Linked To Domain: #{linked_domain.join("; ")}"
          linked_ou_found = linked_ous.join('; ')

          case obj[4]

          when '0'
            print_good 'Status: Enabled'
            gpo_status = 'Enabled'

          when '1'
            print_good 'Status: User Configuration settings are disabled.'
            gpo_status = 'User Configuration settings are disabled'

          when '2'
            print_good 'Status: Computer Configuration settings are disabled.'
            gpo_status = 'Computer Configuration settings are disabled'

          when '3'
            print_good 'Status: Disabled'
            gpo_status = 'Disabled'
          end

          print_good "Machine Extensions: #{obj[5][:value]}"
          print_good "USer Extensions: #{obj[6][:value]}"

          # Initialize WMI fields for loot
          wmifilter_name = ''
          wmifilter_id = ''
          wmifilter_description = ''
          wmifilter_wql = ''

          # get WMI Filter information
          if obj[3][:value].length > 0
            print_good 'WMI Filter:'
            filter_id = obj[3][:value].split(';')[1]

            # GPO can only have on single WMI filter that
            # can have several WQL queries so the array
            # returned will always be of one element.
            matched_filter = wmi_filter_array.select { |filter| filter[:id] == filter_id }
            print_good "\tName: #{matched_filter[0][:name]}"
            wmifilter_name = matched_filter[0][:name]

            print_good "\tId: #{matched_filter[0][:id]}"
            wmifilter_id = matched_filter[0][:id]

            print_good "\tDescription: #{matched_filter[0][:description]}"
            wmifilter_description = matched_filter[0][:description]

            print_good "\tWQL: #{matched_filter[0][:filter].join("; ")}"
            wmifilter_wql = matched_filter[0][:filter]
          end
          table << [
            obj[0][:value], # Id
            obj[1][:value], # Name
            obj[2][:value], # Location
            linked_ou_found,
            gpo_status,
            obj[5][:value], # Machine Extensions
            obj[6][:value], # User Extensions
            wmifilter_name,
            wmifilter_id,
            wmifilter_description,
            wmifilter_wql
          ]
        end

        if datastore['STORE_LOOT']
          stored_path = store_loot('ad.gpo', 'text/plain', session, table.to_csv)
          print_status("Results saved to: #{stored_path}")
        end
      end
    end
  end

  def get_domain
    domain = nil
    begin
      subkey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
      v_name = 'DCName'
      domain_dc = registry_getvaldata(subkey, v_name)
    rescue
      print_error 'Could not determine if the host is part of a domain.'
      return nil
    end
    if !domain_dc.nil?
      # leys parse the information
      dom_info =  domain_dc.split('.')
      domain = dom_info[1].upcase
    else
      print_status 'Host is not part of a domain.'
    end
    domain
  end

  def get_wmifilters(domain)
    # Collect all WMI filters since we will need then to match found GPOs
    vprint_status 'Enumerating all WMI Filters'
    wmi_filters = []
    wmi_mswmi_filter = '(objectClass=msWMI-Som)'
    wmi_fileds = ['msWMI-ID', 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2']

    mswmiquery_result = session.extapi.adsi.domain_query(
                          domain,
                          wmi_mswmi_filter,
                          0,
                          0,
                          wmi_fileds
                        )

    mswmiquery_result[:results].each do |obj|
      wmi_filter = {
        :id => obj[0][:value],
        :name =>  obj[1][:value],
        :description =>  obj[2][:value],
        :filter => obj[3][:value].split(/;\d*;\d*;\d*;\d*WQL;/).drop(1)
      }
      wmi_filters << wmi_filter
    end

    wmi_filters
  end

  def get_lineked_to_ou(domain, ou_id)
    ou_search_filter = "(&(objectclass=organizationalunit)(gplink=*#{ou_id}*))"
    linked_ous = []

    ou_query_result = session.extapi.adsi.domain_query(
                        domain,
                        ou_search_filter,
                        0,
                        0,
                        ['distinguishedname']
                      )

    ou_query_result[:results].each do |obj|
      linked_ous << obj[0][:value]
    end

    linked_ous
  end

  def get_lineked_to_domian(domain, ou_id)
    domain_search_filter = "(&(objectclass=domain)(gplink=*#{ou_id}*))"
    linked_domains = []

  domain_query_result = session.extapi.adsi.domain_query(
                        domain,
                        domain_search_filter,
                        0,
                        0,
                        ['distinguishedname']
                      )

    domain_query_result[:results].each do |obj|
      linked_domains << obj[0][:value]
    end

    linked_domains
  end
end
