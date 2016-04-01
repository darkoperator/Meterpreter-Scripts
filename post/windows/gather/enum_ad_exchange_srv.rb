# encoding: UTF-8

require 'rex'
require 'msf/core'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::ExtAPI

  def initialize(info = {})
    super( update_info(
        info,
        'Name'         => 'Windows Gather Active Directory MS Exchange Servers',
        'Description'  => %Q{
          This module will enumerate MS Exchange Server in the domain the host is
          a member of. Enumeration can be filtered by role.
        },
        'License'       => BSD_LICENSE,
        'Author'        => 'Carlos Perez <carlos_perez[at]darkoperator.com>',
        'Platform'      => 'win',
        'SessionTypes'  => 'meterpreter'
      ))
    # Remove unneeded options
    options.remove_option('FIELDS')
    options.remove_option('DOMAIN')
    options.remove_option('FILTER')

    register_options([
      OptString.new('DOMAIN_DN', [false, 'DN of the domain to enumerate.', nil]),
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
      OptEnum.new('ROLE', [true,
                            'Filter on MS Exchange Server Role.',
                            'ANY', [
                                      'ANY',
                                      'MAIBOX',
                                      'CAS',
                                      'UNIFIED',
                                      'HUB',
                                      'EDGE'
                                    ]
                          ]),
      OptInt.new('MAX_SEARCH', [false, 'Maximum values to retrieve, 0 for all.', 100])

    ], self.class)
  end

  def run
    print_status("Running module against #{sysinfo['Computer']}")
    if load_extapi
      domain_dn = get_dn
      unless domain_dn.nil?

        unless datastore['DOMAIN_DN'].nil?
          domain_dn = datastore['DOMAIN_DN']
        end


        table = Rex::Ui::Text::Table.new(
            'Indent' => 4,
            'SortIndex' => -1,
            'Width' => 80,
            'Columns' =>
            [
              "name", "SerialNumber", "cn"
            ]
          )

        domain = 'CN=Microsoft Exchange,CN=Services,CN=Configuration,' + domain_dn

        inner_filter = '(objectCategory=msExchExchangeServer)'
        case datastore['ROLE']

        when 'ANY'
          role = 'any role'
          inner_filter = "#{inner_filter}"

        when 'MAILBOX'
          role = 'Mailbox Server Role'
          inner_filter = "(#{inner_filter}((msExchCurrentServerRoles:1.2.840.113556.1.4.803:=2)"

        when 'CAS'
          role = 'Client Access Role'
          inner_filter = "(#{inner_filter})(msExchCurrentServerRoles:1.2.840.113556.1.4.803:=4)"

        when 'UNIFIED'
          role = 'Unified Messaging Role'
          inner_filter = "(#{inner_filter})(msExchCurrentServerRoles:1.2.840.113556.1.4.803:=16)"

        when 'HUB'
          role = 'Hub Transport Role'
          inner_filter = "(#{inner_filter})(msExchCurrentServerRoles:1.2.840.113556.1.4.803:=32)"

        when 'EDGE'
          role = 'Edge Transport Role'
          inner_filter = "(#{inner_filter})(msExchCurrentServerRoles:1.2.840.113556.1.4.803:=64)"
        end

        filter =   "(&#{inner_filter})"
        print_status("Performing query for MS Exchange server with #{role}")
        query_result = session.extapi.adsi.domain_query(
                           domain,
                           filter,
                           datastore['MAX_SEARCH'],
                           datastore['MAX_SEARCH'],
                           ["name", "SerialNumber", "cn"]
                         )
        if query_result[:results].length > 0
          query_result[:results].each do |obj|
            table << [obj[0][:value], obj[1][:value], obj[2][:value]]
          end
          table.print
          print_line

          if datastore['STORE_LOOT']
            stored_path = store_loot('ad.exchange.servers', 'text/plain', session, table.to_csv)
            print_status("Results saved to: #{stored_path}")
          end

        else
          print_status("No MS Exchange entries with #{role} found.")
        end
      end
    end
  end

  def get_dn
    dn = nil
    begin
      subkey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
      v_name = 'DCName'
      key_vals = registry_enumvals(subkey)
      if key_vals.include?(v_name)
        domain_dc = registry_getvaldata(subkey, v_name)
        # lets parse the information
        dom_info =  domain_dc.split('.')
        dn = "DC=#{dom_info[1,dom_info.length].join(',DC=')}"
      else
        print_status 'Host is not part of a domain.'
      end
    rescue
      print_error('Could not determine if the host is part of a domain.')
      return nil
    end
    dn
  end

end
