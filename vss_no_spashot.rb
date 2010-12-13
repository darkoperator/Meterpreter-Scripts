# $Id$
# $Revision$
# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################

@client = client
@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ]
)
meter_type = client.platform

################## Function Declarations ##################

# Usage Message Function
#-------------------------------------------------------------------------------
def usage
	print_line "Meterpreter Script for determining places and file extension that"
	print_line "will not be snapshoted by VSS."
	print_line(@exec_opts.usage)
	raise Rex::Script::Completed
end

# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
	print_error("#{meter} version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end

################## Main ##################
@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		usage
	end
}

# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64/i
b = {}
files_not_to_snapshot = []
no_snapshot_key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\BackupRestore\\FilesNotToSnapshot"


registry_enumvals(no_snapshot_key).each do |k|
	value = registry_getvaldata(no_snapshot_key,k).split(/\x00/)
	files_not_to_snapshot << value
end
if files_not_to_snapshot.length > 0
	print_status("Files and folders that will not be Snapshoted:")
	files_not_to_snapshot.each do |e|
		e.each do |r|
			print_good("\t#{r}")
		end
	end
end
