##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'
require 'msf/core/post/windows/extapi'
require 'sqlite3'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::ExtAPI
  include Msf::Post::Windows::Priv
  include Msf::Auxiliary::Report
  include Msf::Post::File


  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Collect Information on a Windows Host.',
      'Description'   => %q{
        Collect Information on a Windows Host.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module against #{sysinfo['Computer']}")

    get_hostinfo
  end

  #-----------------------------------------------------------------------
  def get_hostinfo()
    print_status("######################")
    print_status("# System Information #")
    print_status("######################")
    print_line
    print_status("Target base information:")
    print_good("\tHostname: #{sysinfo['Computer']}")
    print_good("\tDomain: #{sysinfo['Domain']}")
    print_good("\tOS: #{sysinfo['OS']}")
    print_good("\tArchitecture: #{sysinfo['Architecture']}")
    print_good("\tSystem Language: #{sysinfo['System Language']}")
    print_good("\tLogged On Users: #{sysinfo['Logged On Users']}")
    print_line

    print_status("##########################")
    print_status("# Domain Membership Info #")
    print_status("##########################")
    print_line

    print_status('Getting domain membership basic information')
    domajoin = get_dn
    print_good("\tIn Domain: #{domajoin[:in_domain]}")
    print_good("\tDomain Controller: #{domajoin[:domain_controller]}")
    print_good("\tDomain FQDN: #{domajoin[:domain_fqdn]}")
    print_good("\tDomain DN: #{domajoin[:domain_dn]}")
    report_note(
        :host   => session,
        :type   => 'host.info.domain',
        :data   => domajoin ,
        :update => :unique_data
        )
    print_line
    
    print_status("###################################")
    print_status("# Enumerating PowerShell Settings #")
    print_status("###################################")

    print_line
    print_good("Enumerating Windows PowerShell environment")
    enum_powershell

    print_line
    print_status("###################################")
    print_status("# Windows Scripting Host Settings #")
    print_status("###################################")
    
    print_line
    run_wsh_enum
    print_line

    print_line
    print_status("#####################################")
    print_status("# Registered Security Products(WMI) #")
    print_status("#####################################")
    print_line

    get_sec_product2

    print_line
    print_status("###########################")
    print_status("# Verify system processes #")
    print_status("###########################")
    print_line
    
    all_processes = get_processes
    check_processes(all_processes)

    print_line
    print_status("#################################")
    print_status("# Check for Commandline Logging #")
    print_status("#################################")
    print_line


    print_line
    print_status("###############################")
    print_status("# Collecting named pipe names #")
    print_status("###############################")
    collect_pipenames
    print_line


    print_line
    print_status("#####################################")
    print_status("# Collecting Installed Applications #")
    print_status("#####################################")
    print_line
  end

  # Method for getting domain membership info.
  #---------------------------------------------------------------------------------------------
  def get_dn
    domain_membership = {
      in_domain: false,
      domain_dn: '',
      domain_fqdn: '',
      domain_controller: ''
    }

    dn = nil
    begin

      subkey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
      v_name = 'DCName'
      key_vals = registry_enumvals(subkey)
      vprint_status('checking if host is in a domain')
      if key_vals.include?(v_name)
        vprint_status('Host appears to be in a domain.')
        domain_membership[:in_domain] = true
        domain_dc = registry_getvaldata(subkey, v_name)
        domain_membership[:domain_controller] = domain_dc
        # lets parse the information
        dom_info = domain_dc.split('.')
        fqdn = "{dom_info[1,dom_info.length].join('.')}"
        dn = "DC=#{dom_info[1,dom_info.length].join(',DC=')}"
        domain_membership[:domain_fqdn] = fqdn
        domain_membership[:domain_dn] = domain_dn
      else
        vprint_status('Host is not part of a domain.')
      end
    rescue
      vprint_error('Could not determine if the host is part of a domain.')
      return domain_membership
    end
    domain_membership
  end

  #-----------------------------------------------------------------------
  def get_processes
    vprint_status('Collecting current processes.')
    all_processes = session.sys.process.get_processes
    return all_processes
  end

  #-----------------------------------------------------------------------
  def check_processes(all_processes)
    db_path = "#{::Msf::Config.local_directory + File::SEPARATOR }Processes.db"
    if  !File::exist?(db_path)
      print_error("Could not find process database in #{db_path}")
      return
    end

    begin
      db = SQLite3::Database.new(db_path)

      # Check for security products
      tbl = Rex::Text::Table.new(
          'Columns' => [
            'Name',
            'Path',
            'PID',
            'Arch',
            'Comment'
          ])
      print_status('Checking for seurity products.')
      all_processes.each do |proc|
        result = db.execute( "SELECT comment FROM processinformation WHERE name ='#{proc['name']}' AND type = 'SECURITY_PRODUCT'" )
        if result.length > 0
          tbl << [proc['name'], proc['path'], proc['pid'], proc['arch'], "%red#{result[0][0]}%clr"]
        end
      end
      if tbl.rows.length > 0
        print_status('Security Products Processes:')
        print_line tbl.to_s
      else
        print_good('No known security product process found.')
      end

      tbl.rows = []
      print_status('Checking for admin tools.')
      all_processes.each do |proc|
        result = db.execute( "SELECT comment FROM processinformation WHERE (name ='#{proc['name']}' AND type = 'ADMIN_TOOL')" )
        if result.length > 0
          tbl << [proc['name'], proc['path'], proc['pid'], proc['arch'], "%red#{result[0][0]}%clr"]
        end
      end
      if tbl.rows.length > 0
        print_status('Admin Tools Processes:')
        print_line tbl.to_s
      else
        print_good('No known admin tool process found.')
      end

      db.close if db
    rescue SQLite3::Exception => e 
    
      print_error("Exception occurred")
      print_error(e)
    
    ensure
      db.close if db
    end
  end

  # Enumerate users on the target box.
  #-----------------------------------------------------------------------
  def enum_users
    os = sysinfo['OS']
    users = []
    user = session.sys.config.getuid
    path4users = ""
    env_vars = session.sys.config.getenvs('SystemDrive', 'USERNAME')
    sysdrv = env_vars['SystemDrive']

    if os =~ /Windows 7|Vista|2008|2012|2016|8|10/
      path4users = sysdrv + "\\Users\\"
      profilepath = "\\Documents\\WindowsPowerShell\\"
    else
      path4users = sysdrv + "\\Documents and Settings\\"
      profilepath = "\\My Documents\\WindowsPowerShell\\"
    end

    if is_system?
      print_status("Running as SYSTEM extracting user list..")
      session.fs.dir.foreach(path4users) do |u|
        userinfo = {}
        next if u =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService)$/
        userinfo['username'] = u
        userinfo['userappdata'] = path4users + u + profilepath
        users << userinfo
      end
    else
      userinfo = {}
      uservar = env_vars['USERNAME']
      userinfo['username'] = uservar
      userinfo['userappdata'] = path4users + uservar + profilepath
      users << userinfo
    end
    return users
  end

  # Enumerate the profile scripts present and save a copy in loot.
  #-----------------------------------------------------------------------
  def enum_profiles(users)
    tmpout = []
    print_status("Checking if users have Powershell profiles")
    users.each do |u|
      print_status("Checking #{u['username']}")
      begin
        session.fs.dir.foreach(u["userappdata"]) do |p|
          next if p =~ /^(\.|\.\.)$/
          if p =~ /Microsoft.PowerShell_profile.ps1|profile.ps1/i
            ps_profile = session.fs.file.new("#{u["userappdata"]}#{p}", "rb")
            until ps_profile.eof?
              tmpout << ps_profile.read
            end
            ps_profile.close
            if tmpout.length == 1
              print_status("Profile #{p} for #{u["username"]} not empty, it contains:")
              tmpout.each do |l|
                print_line("\t#{l.strip}")
              end
              store_loot("powershell.profile",
                "text/plain",
                session,
                tmpout,
                "#{u["username"]}_#{p}.txt",
                "PowerShell Profile for #{u["username"]}")
            end
          end
        end
      rescue
      end
    end
  end

  # Enumerate the logging settings introduced in PowerShell 4.0
  #-----------------------------------------------------------------------
  def enum_logging(powershell_version)
    if powershell_version.to_i > 3
      mod_log_path = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging"
      script_log_path = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
      transcript_log_path = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription"
      win_pol_path = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows"

      print_status('Checking for logging.')
      if registry_enumkeys(win_pol_path).include?("PowerShell")

        # Check if module loging is enabled
        log_types = registry_enumkeys("#{win_pol_path}\\PowerShell")
        if log_types.include?('ModuleLogging')
          print_status('Module logging configured.')
          mod_log_val = registry_getvaldata( mod_log_path, "EnableModuleLogging" )
          if mod_log_val == 1
            print_good('Module logging is enabled')

            # Check if specific modules are being logged and if they are enum their names.
            if registry_enumkeys(mod_log_path).include?('ModuleNames')
              modnames = []
              registry_enumvals("#{mod_log_path}\\ModuleNames").each do |mname|
                print_good("\tModule: #{mname}")
                modnames << mname
              end
              report_note(
                :host   => session,
                :type   => 'host.log.ps_module',
                :data   => {
                  :enabled => true,
                  :modules => modnames},
                :update => :unique_data
              )
            end
          else
            print_good('Module logging is disabled')
            report_note(
              :host   => session,
              :type   => 'host.log.ps_module',
              :data   => {
                :enabled => false,
                :modules => []},
              :update => :unique_data
            )
          end
        end

        # Check if script block loging is enabled
        if log_types.include?('ScriptBlockLogging')
          print_status('ScriptBlock logging configured.')
          sb_settings = registry_enumvals(script_log_path)
          if sb_settings.include?('EnableScriptBlockLogging')
            block_log = registry_getvaldata(script_log_path,'EnableScriptBlockLogging')
            if block_log == 1
              print_good("\tScript block logging is enabled.")
              report_note(
                :host   => session,
                :type   => 'host.log.ps_scriptblock',
                :data   => {
                  :enabled => true},
                :update => :unique_data
              )
            else
              print_good("\tScript block logging is disabled.")
              report_note(
                :host   => session,
                :type   => 'host.log.ps_scriptblock',
                :data   => {
                  :enabled => false},
                :update => :unique_data
              )
            end
          end

          if sb_settings.include?('EnableScriptBlockInvocationLogging')
            invoke_block_log = registry_getvaldata(script_log_path,'EnableScriptBlockInvocationLogging')
            if invoke_block_log == 1
              print_good("\tScript block invocation logging is enabled.")
              report_note(
                :host   => session,
                :type   => 'host.log.ps_scriptblockinvocation',
                :data   => {
                  :enabled => true},
                :update => :unique_data
              )
            else
              print_good("\tScript block invocation logging is disabled.")
              report_note(
                :host   => session,
                :type   => 'host.log.ps_scriptblockinvocation',
                :data   => {
                  :enabled => false},
                :update => :unique_data
              )
            end
          end
        else
          print_good("\tScriptBlock Loggin is not enabled.")
        end
        # Check if transcription loging is enabled.
        if log_types.include?('Transcription')
          print_status('Transcript configured.')
          transcript_settings = registry_enumvals(transcript_log_path)
          if transcript_settings.include?('EnableTranscripting')
            if registry_getvaldata(transcript_log_path, 'EnableTranscripting') == 1
              print_good("\tTrascript logging is enabled.")
              report_note(
                :host   => session,
                :type   => 'host.log.ps_transcript',
                :data   => {
                  :enabled => true},
                :update => :unique_data
              )
              if transcript_settings.include?('EnableInvocationHeader')
                if registry_getvaldata(transcript_log_path, 'EnableInvocationHeader') == 1
                  print_good("\tInvokation header is enabled for transcript.")
                  report_note(
                    :host   => session,
                    :type   => 'host.log.ps_transcript_invocationheader',
                    :data   => {
                      :enabled => true},
                    :update => :unique_data
                  )
                else
                  print_good("\tInvokation header is not enabled for transcript.")
                  report_note(
                    :host   => session,
                    :type   => 'host.log.ps_transcript_invocationheader',
                    :data   => {
                      :enabled => false},
                    :update => :unique_data
                  )
                end
              end

              if transcript_settings.include?('OutputDirectory')
                transcript_loc = registry_getvaldata(transcript_log_path, 'OutputDirectory')
                if transcript_loc.length > 0
                print_good("\tTrascripts are saved to #{transcript_loc}")
                report_note(
                  :host   => session,
                  :type   => 'host.log.ps_transcript_alt_location',
                  :data   => {
                    :location => transcript_loc},
                  :update => :unique_data
                )
                else
                  print_good("\tTranscript is saved in users Documents folder.")
                end
              else
                print_good("\tTranscript is saved in users Documents folder.")
              end

            else
              print_good("\tTrascript logging is not enabled.")
              report_note(
                :host   => session,
                :type   => 'host.log.ps_transcript',
                :data   => {
                  :enabled => false},
                :update => :unique_data
              )
            end
          else
            print_good("\tTrascript logging is not enabled.")
            report_note(
              :host   => session,
              :type   => 'host.log.ps_transcript',
              :data   => {
                :enabled => false},
              :update => :unique_data
            )
          end
        else
          print_good("\tTranscript Loggin is not enabled.")
        end
      else
        print_good("\tNo PowerShell loggin settings are enabled.")
      end
    end
  end

  # Enumerate the PowerShell version.
  #-----------------------------------------------------------------------
  def enum_version
    if registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\").include?("3")
        powershell_version = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine","PowerShellVersion")
      else
        powershell_version = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine","PowerShellVersion")
      end

      print_good("Version: #{powershell_version}")
      report_note(
        :host   => session,
        :type   => 'host.ps.version',
        :data   => { :version => powershell_version },
        :update => :unique_data
      )
      return powershell_version
  end
  
  # Enumerate the ExecutionPolicy in place for User and Machine.
  #-----------------------------------------------------------------------
  def enum_execpolicy
    # Enumerate the machine policy
    begin
      powershell_machine_policy = registry_getvaldata("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell","ExecutionPolicy")
    rescue
      powershell_machine_policy = "Restricted"
    end

    # Enumerate the User Policy
    begin
      powershell_user_policy = registry_getvaldata("HKCU\\Software\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell","ExecutionPolicy")
    rescue
      powershell_user_policy = "Restricted"
    end
      print_good("Current User Execution Policy: #{powershell_user_policy}")
      print_good("Machine Execution Policy: #{powershell_machine_policy}")
      report_note(
        :host   => session,
        :type   => 'host.ps.execpol.user',
        :data   => { :execpol => powershell_user_policy },
        :update => :unique_data
      )
      report_note(
        :host   => session,
        :type   => 'host.ps.execpol.machine',
        :data   => { :execpol => powershell_machine_policy },
        :update => :unique_data
      )
  end

  #-----------------------------------------------------------------------

  def enum_pssnapins
    powershell_path = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell","Path")
      print_status("Path: #{powershell_path}")
      if registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1").include?("PowerShellSnapIns")
        print_status("Powershell Snap-Ins:")
        registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellSnapIns").each do |si|
          print_status("\tSnap-In: #{si}")
          registry_enumvals("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellSnapIns\\#{si}").each do |v|
            print_status("\t\t#{v}: #{registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellSnapIns\\#{si}",v)}")
          end
        end
      else
        print_status("No PowerShell Snap-Ins are installed")

      end
  end

  # Enumerate all modules found and the  path where they where found.
  #-----------------------------------------------------------------------
  def enum_modules(powershell_version, users)
    if not powershell_version =~ /1./
      print_status("Powershell Modules:")
      powershell_module_path = session.sys.config.getenv('PSModulePath').split(";")
      powershell_module_path.each do |mpath|
        print_good("Enumerating modules at #{mpath}")
        modules_found = []
        session.fs.dir.foreach(mpath) do |m|
          next if m =~ /^(\.|\.\.)$/
          print_good("\t#{m}")
          modules_found << m
        end
        if modules_found.count > 0
          report_note(
            :host   => session,
            :type   => 'host.ps.modules',
            :data   => { :path => mpath,
                         :modules => modules_found },
            :update => :unique_data
          )
        end
      end

      users.each do |u|
        # check if the user has a PowerShell  env setup
        users_mod_path = "#{u['userappdata']}\\Modules"
        if exist?(users_mod_path)
          print_good("Enumerating modules at #{users_mod_path}")
          modules_found = []
          session.fs.dir.foreach(users_mod_path) do |m|
            next if m =~ /^(\.|\.\.)$/
            print_good("\t#{m}")
            modules_found << m
          end
          if modules_found.count > 0
            report_note(
              :host   => session,
              :type   => 'host.ps.modules',
              :data   => { :path => users_mod_path,
                           :modules => modules_found },
              :update => :unique_data
            )
          end
        end
      end
    end
  end

  #-----------------------------------------------------------------------
  def check_ps2enabled
    os = sysinfo['OS']
    if os =~ /Windows 2012|2016|8|10/
      print_status('Checking if PSv2 engine is enabled.')
      path = "HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1"
      if registry_enumkeys(path).include?("PowerShellEngine")
        if registry_getvaldata("#{path}\\PowerShellEngine", 'PowerShellVersion') == '2.0'
          print_good("\tPowerShell 2.0 engine feature is enabled.")
          report_note(
            :host   => session,
            :type   => 'host.log.ps_v2_feature',
            :data   => {
              :enabled => true},
            :update => :unique_data
          )
        else
          print_good("\tPowerShell 2.0 engine feature is not enabled.")
          report_note(
            :host   => session,
            :type   => 'host.log.ps_v2_feature',
            :data   => {
              :enabled => false},
            :update => :unique_data
          )
        end
      end
    end
  end

  #-----------------------------------------------------------------------
  def enum_powershell
    #Check if PowerShell is Installed
    if registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\").include?("PowerShell")
      print_status("Powershell is Installed on this system.")
      users = enum_users
      powershell_version = enum_version
      enum_execpolicy
      enum_pssnapins
      enum_modules(powershell_version, users)
      enum_profiles(users)
      enum_logging(powershell_version)
      check_ps2enabled
    end
  end

  # WSH Functions
  ###########################################################
  def run_wsh_enum()

    settings = get_wsh_settings
    print_status('Windows Scripting Host Settings:')
    trust_pol = check_wsh_winsafer(settings)
    if trust_pol == "0"
      get_wsh_trust_pol(settings)
    end
    show_wsh_exec_error(settings)
  end

  def get_wsh_settings()
    settings_vals = registry_enumvals('HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings')
    return settings_vals
  end

  def check_wsh_winsafer(settings)
    setting_key = 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings'
    if settings.include?('UseWINSAFER')

      policy_setting = registry_getvaldata(setting_key, 'UseWINSAFER')

      if policy_setting == "1"
        print_good("\tPolicy: SRP")
      else
        print_good("\tPolicy: TrustPolicy")
      end

    end
    return policy_setting
  end

  def get_wsh_trust_pol(settings, system = true)
    if settings.include?('TrustPolicy')

      if system
        setting_key = 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings'
      else
        setting_key = 'HCU\SOFTWARE\Microsoft\Windows Script Host\Settings'
      end

      trust_policy_setting = registry_getvaldata(setting_key, 'TrustPolicy')

      if trust_policy_setting == "0"
        print_good("\tTrust Policy: Run All Scripts")
      elsif trust_policy_setting == "1"
        print_good("\tTrust Policy: Promp to Run")
      elsif trust_policy_setting == "2"
        print_good("\tTrust Policy: All Signed")
      end

    else
      print_good("\tTrust Policy: NOT SET")
    end
  end

  def show_wsh_exec_error(settings)
    setting_key = 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings'
    if settings.include?('SilentTerminate')
      policy_setting = registry_getvaldata(setting_key, 'SilentTerminate')
      if policy_setting == "0"
        print_good("\tError Message: Supress")
      else
        print_good("\tError Message: Showr")
      end
    end
  end

  ########################################
  # WMI Enumeration of Security Products #
  ########################################

  def get_sec_product2()
    extapi_loaded = load_extapi
    if !extapi_loaded
        print_error "ExtAPI failed to load"
        return
    end
    queries = []
    
    queries << {
      :query => "SELECT displayName,pathToSignedProductExe,productState FROM AntiVirusProduct",
      :product => 'AntiVirus'}
    queries << {
      :query => "SELECT displayName,pathToSignedProductExe,productState FROM AntiSpywareProduct",
      :product => 'AntiSpyware'}
    queries << {
      :query => "SELECT displayName,pathToSignedProductExe,productState FROM FirewallProduct",
      :product => 'Firewall'}

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

  def collect_pipenames()
    pipe_names = []
    session.fs.dir.foreach('\\\\.\\pipe\\\\') do |pipe|
        pipe_names << pipe
    end
    print_good("\tCollected #{pipe_names.length} pipe names.")
    report_note(
              :host   => session,
              :type   => 'host.info.pipes',
              :data   => {
                :names => pipe_names},
              :update => :unique)
  end
end
