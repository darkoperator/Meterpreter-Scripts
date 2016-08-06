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
          'Name'          => 'Windows Gather AD Enumerate Domain Trusts',
          'Description'   => %q{ This Module will perform an ADSI query and
          enumerate all Domain Trusts on the domain},
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

        table = Rex::Ui::Text::Table.new(
          'Indent' => 4,
          'SortIndex' => -1,
          'Width' => 80,
          'Columns' =>
          [
            'Name',
            'NetBIOS Name',
            'Trust Direction',
            'Trust Type'
          ]
        )

        filter =   '(objectClass=trustedDomain)'
        query_result = session.extapi.adsi.domain_query(
                         domain,
                         filter,
                         datastore['MAX_SEARCH'],
                         datastore['MAX_SEARCH'],
                         ['TrustPartner',
                          'flatName',
                          'trustDirection',
                          'trustType'
                        ]
                       )
        if query_result[:results].empty?
          print_status 'No results where found.'
          return
        end

        query_result[:results].each do |obj|

          # Case for Trust Direction
          case obj[2][:value]
          when '0'
            trust_direction = 'Disabled'
          when '1'
            trust_direction = 'Inbound trust'
          when '2'
            trust_direction = 'Outbound trust'
          when '3'
            trust_direction = 'Two-way trust'
          end

          # Case for trust type
          case obj[3][:value]
          when '1'
            trust_type = 'Down Level, Windows Domain not running AD'
          when '2'
            trust_type = 'Up Level, Windows Domain running AD'
          when '3'
            trust_type = 'MIT, None Windows RFC4120-compliant Kerberos'
          when '4'
            trust_type = 'DCE'
          end

          table << [obj[0][:value], obj[1][:value], trust_direction, trust_type]
        end
        table.print
        print_line

        if datastore['STORE_LOOT']
          stored_path = store_loot(
                          'ad.trusts',
                          'text/plain',
                          session,
                          table.to_csv)
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
