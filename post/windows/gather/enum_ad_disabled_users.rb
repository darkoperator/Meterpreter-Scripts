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
          'Name' => 'Windows Gather AD Enumerate Domain Disabled User',
          'Description'   => %q{ This Module will perform an ADSI
          query and enumerate disabled user accounts for a given
          user on the domain the host is a member of through a
          Windows Meterpreter Session.},
          'License'       => BSD_LICENSE,
          'Author'        => 'Carlos Perez <carlos_perez[at]darkoperator.com>',
          'Platform'      => 'win',
          'SessionTypes'  => 'meterpreter'
      ))
    register_options(
      [
        OptString.new('DOMAIN_DN', [false, 'DN of the domain to enumerate.', nil]),
        OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
        OptInt.new('MAX_SEARCH', [false, 'Maximum values to retrieve, 0 for all.', 100])
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

        vprint_good("Running query against domain #{domain}")
        result_table = Rex::Ui::Text::Table.new(
          'Indent' => 4,
          'SortIndex' => -1,
          'Width' => 80,
          'Columns' =>
          %w{
            'SAMAccount',
            'Email',
            'Comment',
            'Primary_Group_ID',
            'DistinguishedName'
          }
        )
        filter =   '(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=2))'
        query_result = session.extapi.adsi.domain_query(
                          domain,
                          filter,
                          datastore['MAX_SEARCH'],
                          datastore['MAX_SEARCH'],
                          [
                            'samaccountname',
                            'mail',
                            'comment',
                            'primarygroupid',
                            'distinguishedname'
                          ]
                       )
        if query_result[:results].empty?
          print_status 'No results where found.'
          return
        end

        query_result[:results].each do |obj|
          result_table << [obj[0][:value], obj[1][:value], obj[2][:value], obj[3][:value], obj[4][:value]]
        end
        result_table.print
        print_line

        if datastore['STORE_LOOT']
          stored_path = store_loot(
                           'ad.disabled_users',
                           'text/plain',
                           session,
                           result_table.to_csv
                        )
          print_status("Results saved to: #{stored_path}")
        end

      end
    end
  end

  def check_domain
    domain = nil
    begin
      subkey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
      v_name = 'DCName'
      domain_dc = registry_getvaldata(subkey, v_name)
    rescue
      print_error 'Could not determine if the host is part of a domain.'
    end

    if !domain_dc.nil?
      # lets parse the information
      dom_info =  domain_dc.split('.')
      domain = dom_info[1].upcase
    else
      print_status 'Host is not part of a domain.'
    end
    domain
  end
end
