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
class windows_snmp
(
  String $community,
  String $syscontact,
  String $syslocation,
  String $permitted_managers
)
{
  # Install the Windows Feature
  dsc_windowsfeature  { 'SNMP Service':
    dsc_ensure => 'Present',
    dsc_name   => 'SNMP-Service',
  }

  $reg_basepath = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters'

  dsc_registry {
    default:
      dsc_ensure => 'Present',
      require    => Dsc_windowsfeature['SNMP Service'],
    ;
    ['Permitted SNMP managers']:
      dsc_key       => "${reg_basepath}\PermittedManagers",
      dsc_valuename => '1',
      dsc_valuedata => $permitted_managers,
    ;
    ['System contact information']:
      dsc_key       => "${reg_basepath}\RFC1156Agent",
      dsc_valuename => 'sysContact',
      dsc_valuedata => $syscontact,
    ;
    ['System location information']:
      dsc_key       => "${reg_basepath}\RFC1156Agent",
      dsc_valuename => 'sysLocation',
      dsc_valuedata => $syslocation,
    ;
    ['SNMP trap destination']:
      dsc_key       => "${reg_basepath}\TrapConfiguration",
      dsc_valuename => '1',
      dsc_valuedata => $permitted_managers,
    ;
    ['SNMP community string']:
      dsc_key       => "${reg_basepath}\ValidCommunities",
      dsc_valuename => '1',
      dsc_valuedata => $community,
    ;
  }
}


