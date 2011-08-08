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
require 'msf/core/post/common'


class Metasploit3 < Msf::Post

	include Msf::Post::Common


	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Multi Gather DNS Forward Lookup Bruteforce',
				'Description'   => %q{ 
					Brute force subdomains and hostnames via wordlist.
				},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows','linux', 'osx', 'bsd', 'solaris' ],
				'SessionTypes'  => [ 'meterpreter','shell' ]
			))
		register_options(
			[

				OptString.new('DOMAIN', [true, 'Domain ro perform SRV query against.']),
				OptPath.new('NAMELIST',[true, "List of hostnames or subdomains to use.",
						::File.join(Msf::Config.install_root, "data", "wordlists", "namelist.txt")])

			], self.class)
	end

	# Run Method for when run command is issued
	def run
		
		domain = datastore['DOMAIN']
		hostlst = datastore['NAMELIST']
		print_status("Performing DNS Forward Lookup Bruteforce for Domain #{domain}")

		i, a = 0, []


		if session.type =~ /shell/
			# Only one thread possible when shell
			thread_num = 1
		else
			# When Meterpreter the safest thread number is 10
			thread_num = 10
		end


		if ::File.exists?(hostlst)
			::File.open(hostlst).each do |n|
				# Set count option for ping command
				plat = session.platform
				case plat
				when /win/i
					ns_opt = " #{n.strip}.#{domain}"
					cmd = "nslookup"
				when /solaris/i
					ns_opt = " #{n.strip}.#{domain}"
					cmd = "/usr/sbin/host"
				else
					ns_opt = " #{n.strip}.#{domain}"
					cmd = "/usr/bin/host"
				end

				if i < thread_num
					a.push(::Thread.new {
							r = cmd_exec(cmd, ns_opt)

							case plat
							when /win/
								puts r
							else
								r.each_line do |l|
									target,ip = l.scan(/(\S*) has address (\S*)$/).join
									if target != ""
										print_status("RECORD:#{n.strip}.#{domain} TARGET:#{target} " + "IP:#{ip}")
									end
								end
							end

						})
					i += 1
				else
					sleep(0.05) and a.delete_if {|x| not x.alive?} while not a.empty?
					i = 0
				end
			end
			a.delete_if {|x| not x.alive?} while not a.empty?
		else
			print_error("Name list file specified does not exist.")
		end

	end




	def get_ip(host)
		ip_add = []
		cmd_exec("host"," #{host}").each_line do |l|
			ip =""
			ip = l.scan(/has address (\S*)$/).join
			ip_add << ip if ip != ""
		end
		return ip_add
	end

	def host_srv_consume(host_out)
		srv_records = []
		# Parse for SRV Records
		host_out.each_line do |l|
			if l =~ /has SRV/
				record,port,target = l.scan(/(\S*) has SRV record \d*\s\d*\s(\d*)\s(\S*)/)[0]
				if Rex::Socket.dotted_ip?(target)
					rcrd ={}
					rcrd[:srv] = record
					rcrd[:port] = port
					rcrd[:target] = target
					rcrd[:ip] = target
					srv_records << rcrd
				else
					get_ip(target).each do |i|
						rcrd ={}
						rcrd[:srv] = record
						rcrd[:port] = port
						rcrd[:target] = target
						rcrd[:ip] = i
						srv_records << rcrd
					end
				end
			end
		end
		return srv_records
	end
end