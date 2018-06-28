# Setup SNMP (client) feature in Windows
#
# == Parameters:
#
# $community:: community string
#
# $syscontact:: system contact, usually an email address
#
# $syslocation:: location of the node
#
# $permitted_managers:: IP address or DNS name to allow connections from
#
# $enable_authtraps:: Enable authentication traps (default: false)
#
# $manage_packetfilter:: whether to open port 161 in Windows Firewall (default: true)
#
# $allow_address_ipv4:: IP address(es) or network(s) to allow SNMP connections from (string or array, default: '127.0.0.1').
#
class windows_snmp
(
  String                        $community,
  String                        $syscontact,
  String                        $syslocation,
  String                        $permitted_managers,
  Boolean                       $enable_authtraps = false,
  Boolean                       $manage_packetfilter = true,
  Variant[String,Array[String]] $allow_address_ipv4 = '127.0.0.1'
)
{

  # Install the Windows SNMP Feature. This is done differently in
  # desktop and server versions
  case $facts['os']['release']['major'] {
    /(2008 R2|2012 R2|2016)/: {
      dsc_windowsfeature { 'SNMP Service':
        dsc_ensure => 'Present',
        dsc_name   => 'SNMP-Service',
      }
      $feature_require = Dsc_windowsfeature['SNMP Service']
    }
    default: {
      dsc_windowsoptionalfeature { 'SNMP Service':
        dsc_ensure => 'Enable',
        dsc_name   => 'SNMP',
      }
      $feature_require = Dsc_windowsoptionalfeature['SNMP Service']
    }
  }

  $reg_basepath = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters'

  dsc_registry {
    default:
      dsc_ensure => 'Present',
      require    => $feature_require,
    ;
    ['Permitted SNMP managers']:
      dsc_key       => "${reg_basepath}\\PermittedManagers",
      dsc_valuename => '1',
      dsc_valuedata => $permitted_managers,
    ;
    ['System contact information']:
      dsc_key       => "${reg_basepath}\\RFC1156Agent",
      dsc_valuename => 'sysContact',
      dsc_valuedata => $syscontact,
    ;
    ['System location information']:
      dsc_key       => "${reg_basepath}\\RFC1156Agent",
      dsc_valuename => 'sysLocation',
      dsc_valuedata => $syslocation,
    ;
    ['SNMP trap destination']:
      dsc_key       => "${reg_basepath}\\TrapConfiguration",
      dsc_valuename => '1',
      dsc_valuedata => $permitted_managers,
    ;
    ['SNMP community string']:
      dsc_key       => "${reg_basepath}\\ValidCommunities",
      dsc_valuename => '1',
      dsc_valuedata => $community,
    ;
  }

  if $enable_authtraps {
    dsc_registry { 'Enable authentication traps':
      dsc_ensure    => 'Present',
      dsc_key       => $reg_basepath,
      dsc_valuename => 'EnableAuthenticationTraps',
      dsc_valuedata => '1',
      require       => Dsc_windowsfeature['SNMP Service'],
    }
  }

  if $manage_packetfilter {

    $allow_address_ipv4_array = any2array($allow_address_ipv4)
    $remote_ips = join($allow_address_ipv4_array, ',')

    ::windows_firewall::exception { 'windows_snmp':
      ensure       => 'present',
      direction    => 'in',
      action       => 'Allow',
      enabled      => 'yes',
      protocol     => 'UDP',
      local_port   => '161',
      remote_ip    => $remote_ips,
      display_name => "SNMP-in from ${remote_ips}",
      description  => "Allow SNMP connections from ${remote_ips} to udp port 161",
    }
  }
}
