# This script creates the Datasources.xml file in the syslog policies directory of your domain controller for detecting SYSVOL enumeration with tools such as CrackMapExec and Impacket
Import-Module ActiveDirectory
Add-Type -AssemblyName System.Web

# Check if Datasources.xml already exists
if (Test-Path -Path "C:\Windows\SYSVOL\domain\Policies\Datasources.xml") {
    Write-Error "Error: Datasources.xml already exists."
    exit 1
}

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
