# This script creates the Datasources.xml and Registry.xml file in the syslog policies directory of your domain controller for detecting SYSVOL enumeration with tools such as CrackMapExec and Impacket
Import-Module ActiveDirectory
Add-Type -AssemblyName System.Web

# Check if Datasources.xml already exists
if (Test-Path -Path "C:\Windows\SYSVOL\domain\Policies\Datasources.xml") {
    Write-Warning "Datasources.xml already exists."
} else {

# Generate random $plaintext and $encryptedtext
$plainText = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_})
$key = New-Object Byte[] 16
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
$encryptedText = [System.Convert]::ToBase64String($key) + '::' + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($plainText))

# Create Datasources.xml file
$DatasourcesXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<datasource-mapping>
    <datasource>
        <catalog-connection-name>Connection1</catalog-connection-name>
        <connection-type>JDBC</connection-type>
        <driver>sun.jdbc.odbc.JdbcOdbcDriver</driver>
        <url>jdbc:odbc</url>
        <user>$plaintext</user>
        <password>$encryptedText</password>
    </datasource>
</datasource-mapping>
"@

# Save Datasources.xml file
$DatasourcesXml | Out-File -Encoding utf8 "C:\Windows\SYSVOL\domain\Policies\Datasources.xml"

# Set Advanced Security Audit Settings
$acl = Get-Acl "C:\Windows\SYSVOL\domain\Policies\Datasources.xml"
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "ReadAndExecute", "Success,Failure")
$acl.AddAuditRule($auditRule)
Set-Acl "C:\Windows\SYSVOL\domain\Policies\Datasources.xml" $acl

# Set file permissions
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "ReadAndExecute", "Deny")
$acl.SetAccessRule($rule)
Set-Acl "C:\Windows\SYSVOL\domain\Policies\Datasources.xml" $acl

Write-Host "Success! Datasources.xml honey file created at C:\Windows\SYSVOL\domain\Policies\Datasources.xml on $env:computername" -ForegroundColor green
}

if (Test-Path -Path "C:\Windows\SYSVOL\domain\Policies\Registry.xml") {
    Write-Warning "Registry.xml already exists."
} else {

#Create Registry.xml file
$RegistryXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Registry clsid="{9CD22E48-1225-4A05-8D14-4B4C4AE4CB7E}" 
          hiveName="HKLM" 
          keyName="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 
          action="create">
  <Value name="AutoAdminLogon" 
         type="REG_SZ" 
         value="1"/>
  <Value name="DefaultUserName" 
         type="REG_SZ" 
         value="$plaintext"/>
  <Value name="DefaultPassword" 
         type="REG_SZ" 
         value="$encryptedText"/>
  <Value name="DefaultDomainName" 
         type="REG_SZ" 
         value="local"/>
</Registry>
"@

# Save Registry.xml file
$RegistryXml | Out-File -Encoding utf8 "C:\Windows\SYSVOL\domain\Policies\Registry.xml"

# Set Advanced Security Audit Settings
$acl = Get-Acl "C:\Windows\SYSVOL\domain\Policies\Registry.xml"
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "ReadAndExecute", "Success,Failure")
$acl.AddAuditRule($auditRule)
Set-Acl "C:\Windows\SYSVOL\domain\Policies\Registry.xml" $acl

# Set file permissions
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "ReadAndExecute", "Deny")
$acl.SetAccessRule($rule)
Set-Acl "C:\Windows\SYSVOL\domain\Policies\Registry.xml" $acl

Write-Host "Success! Registry.xml honey file created at C:\Windows\SYSVOL\domain\Policies\Registry.xml on $env:computername" -ForegroundColor green
}
