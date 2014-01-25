require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::ExtAPI

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather AD Enumerate Domain Grooup Membership',
        'Description'   => %q{ This Module will perform an ADSI query and enumerate
          all members of a given security group given its Distinguished Name on
          the domain the host is a member of through a Windows Meterpreter Session.},
        'License'       => BSD_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter']
      ))
    register_options(
      [
        OptString.new('GROUP_DN', [true, 'Distinguished Name of the group or Organizational Unit to enumerate members.', nil]),
        OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
        OptInt.new('MAX', [false, 'The number of maximun results to enumerate.', 100])
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
            'SAMAccount',
            'DistinguishedName',
            'Type'
          ]
        )

        filter =   "(memberOf=#{datastore['GROUP_DN']})"
        query_result = session.extapi.adsi.domain_query(domain,
                                                        filter,
                                                        datastore['MAX'],
                                                        datastore['MAX'],
                                                        ["name", "samaccountname","distinguishedname",'objectcategory']
                                                      )
        query_result[:results].each do |obj|

          # Identify the object type
          objtype = ""
          case obj[3].to_s
          when /^CN=Person*/
            objtype = "User"
          when /^CN=Computer/
            objtype = "Computer"
          when /^CN=Group*/
            objtype = "Group"
          end

          table << [obj[0], obj[1], obj[2], objtype]
        end
        table.print
        print_line

        if datastore['STORE_LOOT']
          stored_path = store_loot('ad.groups_members', 'text/plain', session, table.to_csv)
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
