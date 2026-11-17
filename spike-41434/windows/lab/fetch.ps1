# Copies the ETW logs and ground-truth files from a lab VM to ..\out.
param([int]$Port = 5985, [string]$User = 'vagrant', [string]$Password = 'vagrant', [string]$Out = (Join-Path $PSScriptRoot '..\out'))
$cred = New-Object System.Management.Automation.PSCredential($User, (ConvertTo-SecureString $Password -AsPlainText -Force))
$s = New-PSSession -ComputerName 127.0.0.1 -Port $Port -Credential $cred -Authentication Negotiate
New-Item -ItemType Directory -Force $Out | Out-Null
Copy-Item -FromSession $s -Path 'C:\poc41434\*.txt', 'C:\poc41434\*.csv' -Destination $Out -Force
Remove-PSSession $s
