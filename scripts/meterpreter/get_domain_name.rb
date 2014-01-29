session = client

@@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false,"Help menu." ]
)

# Gets the Domain Name
def get_domain(session)
  domain = ""
  ipv4_info = nil
  ipv6_info = nil
  begin
    subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
    v_name = "DCName"
    domain_dc = registry_getvaldata(subkey, v_name)
  rescue
    print_error("Could not determine if the host is part of a domain.")
  end
  if (!domain_dc.nil?)
    # leys parse the information
    dom_info =  domain_dc.split('.')
    domain = dom_info[1].upcase
    dc = domain_dc.gsub('\\\\','')
    print_good("Domain: #{domain}")
    print_good("Domain Controller: #{dc}")

    # Resolve IPv4 address
    begin
      ipv4_info = session.net.resolve.resolve_host(dc, AF_INET)
      print_good("IPv4: #{ipv4_info[:ip]}")

    rescue
      print_status("Could not resolve IPv4 for #{dc}")
    end

    # Resolve IPv6 address
    begin
      ipv6_info = session.net.resolve.resolve_host(dc, AF_INET6)
      print_good("IPv6: #{ipv6_info[:ip]}")
    rescue
      print_status("Could not resolve IPv6 for #{dc}")
    end

  else
    print_status "Host is not part of a domain."
  end
end

@@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    print_line "Meterpreter Script for showing the domain name and prefered domain a host is a  member of and the prefered DC."
    print_line "Author: Carlos Perez <carlos_perez[at]darkoperator.com>"
    print_line(@@exec_opts.usage)
    raise Rex::Script::Completed
  end
}

get_domain
raise Rex::Script::Completed
