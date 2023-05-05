# SYSVOL_enum_honeyxml

## Purpose
A powershell script for detecting SYSVOL enumeration. SYSVOL is enumerated by several tools including CrackMapExec and Impacket. They scan the SYSVOL directory of a windows domain, looking for saved passwords on domain controllers. By adding this file along with file auditing you can detect such a scan in your environment. For more information click here.

## Instructions

1. Save the create_honeydir.ps1 file on your domain controller.
2. Open a powershell command prompt on your domain controller and run as Admin.
3. Run create_honeydir.ps1 to create the groups.xml file in "C:\Windows\SYSVOL\domain\Policies\"
4. If you aren't already seeing 5145 security logs, you can enable them by using the following setting in your GPO:

       Computer Configuraion>Policies>Windows Settings>Security Settings>Advanced Audit Policy Configuration>Object Access>Audit Detailed File Share

and select both "Success" and "Failure"

## Detection Criteria
    type=windows
    windows_event_id=5145
    file_path like 'groups.xml'
    
 The subject_account_name will always be the account that was compromised by the attacker, which means they either have the password or the password hash.
