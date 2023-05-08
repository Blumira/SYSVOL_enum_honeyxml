# SYSVOL_enum_honeyxml

## Purpose
A powershell script for detecting SYSVOL enumeration with two files with fake credentials. SYSVOL is enumerated by several tools including CrackMapExec and Impacket. They scan the SYSVOL directory of a windows domain, looking for saved passwords on domain controllers. By adding this file along with file auditing you can detect such a scan in your environment. For more information click here.

## Instructions

1. Save the create_honeydir.ps1 file on your domain controller.
2. Open a powershell command prompt on your domain controller and run as Admin.
3. Run create_honeyxml.ps1 to create both the registry.xml and datasources.xml files in "C:\Windows\SYSVOL\domain\Policies\"
4. If you aren't already seeing 5145 security logs, you can enable them by using the following setting in your GPO:

       Computer Configuraion>Policies>Windows Settings>Security Settings>Advanced Audit Policy Configuration>Object Access>Audit Detailed File Share

and select both "Success" and "Failure"

## Detection Criteria
    type='windows'
    windows_event_id in (5145)
    file_path contains 'Registry.xml' or '%DataSources.xml'
    object_path like '%SYSVOL%'
    
NOTE: The subject_account_name will always be the account that was compromised by the attacker, which means they either have the password or the password hash. Based on our testing there are very many potential FPs due to the amount of vulnerability scanners, backup solutions, etc in an environment, so it should be tuned depending on those activities being present.
