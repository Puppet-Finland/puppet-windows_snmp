# @summary Setup SNMP (client) feature in Windows
#
# @param community
#   community string
#
# @param syscontact
#   system contact, usually an email address
#
# @param syslocation
#   location of the node
#
# @param permitted_managers
#   IP address or DNS name to allow connections from
#
# @param enable_authtraps
#   Enable authentication traps
#
# @param manage_packetfilter
#   Whether to open port 161 in Windows Firewall
#
# @param snmp_client_version
#   The version of SNMP.Client capability to install. Only affects recent
#   Windows 10 versions where SNMP is not feature but a capability.
#
# @param allow_address_ipv4
#   IP address(es) or network(s) to allow SNMP connections from
#
class windows_snmp
(
  String                        $community,
  String                        $syscontact,
  String                        $syslocation,
  String                        $permitted_managers,
  Boolean                       $manage = true,
  Boolean                       $enable_authtraps = false,
  Boolean                       $manage_packetfilter = true,
  String                        $snmp_client_version = '0.0.1.0',
  Variant[String,Array[String]] $allow_address_ipv4 = '127.0.0.1'
)
{

  if $manage {
  # Install the Windows SNMP Feature. This is done differently in
  # desktop and server versions
  case $facts['os']['release']['major'] {
    /(2008 R2|2012 R2|2016|2019)/: {
      dsc_windowsfeature { 'SNMP Service':
        dsc_ensure => 'Present',
        dsc_name   => 'SNMP-Service',
      }
      $feature_require = Dsc_windowsfeature['SNMP Service']
    }
    /(10)/: {
      # SNMP turned from a Feature to a Capability at some point. While Powershell DSC has support for WindowsCapabilities the Puppet wrapper
      # has not arrived to puppetlabs-dsc yet:
      #
      # <https://github.com/PowerShell/ComputerManagementDsc/tree/dev/DSCResources/MSFT_WindowsCapability>
      # <https://github.com/puppetlabs/puppetlabs-dsc/tree/master/lib/puppet/type>
      #
      # So, for now, add the feature with raw Powershell.
      exec { 'add-snmp-capability':
        command  => "Add-WindowsCapability -Online -Name \"SNMP.Client~~~~${snmp_client_version}\"",
        unless   => 'if (Get-Service -ErrorAction SilentlyContinue SNMP) { exit 0 }',
        provider => 'powershell',
      }
      $feature_require = Exec['add-snmp-capability']
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
      action       => 'allow',
      enabled      => true,
      protocol     => 'UDP',
      local_port   => 161,
      remote_ip    => $remote_ips,
      display_name => "SNMP-in from ${remote_ips}",
      description  => "Allow SNMP connections from ${remote_ips} to udp port 161",
    }
  }
  }
}
