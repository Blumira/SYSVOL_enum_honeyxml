# This script creates the groups.xml file in the syslog policies directory of your domain controller for detecting SYSVOL enumeration with tools such as CrackMapExec and Impacket
Import-Module ActiveDirectory
add-type -AssemblyName System.Web

# Generate random strings
$randomStrings = 1..10 | ForEach-Object { [System.Web.Security.Membership]::GeneratePassword(32,4) }

# Create Groups.xml file
$groupsXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="$($randomStrings[0])" disabled="1">
 <User clsid="$($randomStrings[1])" name="$($randomStrings[9])" image="2" changed="$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))" uid="$($randomStrings[2])">
 <Properties
 action="U"
 newName=""
 fullName="$($randomStrings[3])"
 description="$($randomStrings[4])"
 cpassword="$($randomStrings[5])"
 changeLogon="0"
 noChange="0"
 neverExpires="0"
 acctDisabled="1"
 userName="$($randomStrings[6])"/>
 </User>
 <Group clsid="$($randomStrings[7])" name="$($randomStrings[8])" image="2" changed="$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))" uid="$($randomStrings[9])">
 <Properties
 action="U"
 newName=""
 description="$($randomStrings[4])"
 userAction="REMOVE"
 deleteAllUsers="1"
 deleteAllGroups="1"
 removeAccounts="0"
 groupName="$($randomStrings[8])">
 <Members>
 <Member
 name="domain\sampleuser"
 action="ADD"
 sid=""/>
 </Members>
 </Properties>
 </Group>
</Groups>
"@

# Save Groups.xml file
$groupsXml | Out-File -Encoding utf8 "C:\Windows\SYSVOL\domain\Policies\groups.xml"

# Set Advanced Security Audit Settings
$acl = Get-Acl "C:\Windows\SYSVOL\domain\Policies\groups.xml"
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "ReadAndExecute", "Success,Failure")
$acl.AddAuditRule($auditRule)
Set-Acl "C:\Windows\SYSVOL\domain\Policies\groups.xml" $acl

# Set file permissions
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "ReadAndExecute", "Deny")
$acl.SetAccessRule($rule)
Set-Acl "C:\Windows\SYSVOL\domain\Policies\groups.xml" $acl
