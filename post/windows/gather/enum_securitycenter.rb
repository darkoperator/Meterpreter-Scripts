require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/extapi'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::Windows::ExtAPI

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Enumerate registered AV, AntiMalware and Firewall solutions.',
      'Description'   => %q{
        This module enumerates AV, AntiMalware and Firewall solutionsregistered with Windows Security
        Center.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
    register_options([
      OptEnum.new('PRODUCT', [true,
                            'Security product to query for.',
                            'ALL', [
                                      'AV',
                                      'SPYWARE',
                                      'FIREWALL',
                                      'ALL'
                                    ]
                          ])

    ], self.class)
  end

  def run()
    print_status("Running post module against #{sysinfo['Computer']}")
    extapi_loaded = load_extapi
    if extapi_loaded
        get_sec_product2(datastore['PRODUCT'])
    else
        print_error "ExtAPI failed to load"
    end
  end

  def get_sec_product2(product)
    queries = []
    case product
    when 'AV'
        queries << {
            :query => "SELECT displayName,pathToSignedProductExe,productState FROM AntiVirusProduct",
            :product => 'AntiVirus'}
    when 'SPYWARE'
        queries << {
            :query => "SELECT displayName,pathToSignedProductExe,productState FROM AntiSpywareProduct",
            :product => 'AntiSpyware'}
    when 'FIREWALL'
        queries << {
          :query => "SELECT displayName,pathToSignedProductExe,productState FROM FirewallProduct",
          :product => 'Firewall'}
    when 'ALL'
        queries << {
          :query => "SELECT displayName,pathToSignedProductExe,productState FROM AntiVirusProduct",
          :product => 'AntiVirus'}
        queries << {
          :query => "SELECT displayName,pathToSignedProductExe,productState FROM AntiSpywareProduct",
          :product => 'AntiSpyware'}
        queries << {
          :query => "SELECT displayName,pathToSignedProductExe,productState FROM FirewallProduct",
          :product => 'Firewall'}
    end

    queries.each do |q|
        begin
            objects = session.extapi.wmi.query(q[:query],'root\securitycenter2')
            print_status("Enumerating registed #{q[:product]}")
            if objects
              objects[:values].each do |o|
                print_good("\tName: #{o[0]}")
                print_good("\tPath: #{o[1]}")
                status_bit = o[2].to_i.to_s(16).slice(1,1)
                if status_bit == '1'
                  status = 'Enabled'
                elsif status_bit == '0'
                  status = 'Disabled'
                else
                  status = 'Unknown'
                end
                print_good("\tStatus: #{status}")
                print_good(" ")
              end
            end
         rescue RuntimeError
           print_error "A runtime error was encountered when querying for #{q[:product]}"
        end
    end
  end
end
