# encoding: UTF-8

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::ExtAPI

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Windows Gather AD Enumerate Domain Group Memebership',
                      'Description'   => %q{ This Module will perform an ADSI query and enumerate
                        group membership for a given user on the domain the host is a member
                        of through a Windows Meterpreter Session.},
                      'License'       => BSD_LICENSE,
                      'Author'        => 'Carlos Perez <carlos_perez[at]darkoperator.com>',
                      'Platform'      => 'win',
                      'SessionTypes'  => 'meterpreter'
      ))
    register_options(
      [
        OptString.new('SAMACCOUNT', [true,
                                     'SAM account name for the user to enumerate membership of.',
                                     nil])
      ], self.class)
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")

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
            'Group'
          ]
        )
        filter =   "(&(objectClass=user)(samAccountName=#{datastore["SAMACCOUNT"]}))"
        query_result = session.extapi.adsi.domain_query(domain,
                                                        filter,
                                                        1,
                                                        1,
                                                        ['memberof']
                                                      )
        if query_result[:results].empty?
          print_status 'No results where found.'
          return
        end

        query_result[:results].each do |obj|
          table << obj
        end
        table.print
        print_line
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
      print_error('Could not determine if the host is part of a domain.')
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
end
