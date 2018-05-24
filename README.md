# windows_snmp

A Puppet module for configuring SNMP (client) feature on Windows and opening up
holes in to the Windows Firewall.

# Usage

Typical usage:

    class { '::windows_snmp':
      community           => 'public',
      syscontact          => 'admin@example.org',
      permitted_managers  => '10.16.130.15',
      allow_address_ipv4  => [ '10.16.130.15', '192.168.70.0/24' ],
      syslocation         => 'Pleasanton, CA',
    }

The $permitted_managers parameter can take either and IP address or a hostname. 
Windows itself supports multiple values for the permitted_managers registry key, 
but this module currently only supports defining one.

The $allow_address_ipv4 parameter gets passed to puppet/windows_firewall and 
from there to the "netsh advfirewall" command. It can take either a single 
IP/network as a string, or multiple as an array of strings. Firewall management 
can be turned off by setting $manage_packetfilter to false.
