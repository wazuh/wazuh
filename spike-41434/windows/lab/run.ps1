# Runs a script block in a lab VM over PowerShell Remoting; -Copy first copies the binaries and scripts to C:\poc41434.
param([string]$Script, [switch]$Copy, [int]$Port = 5985, [string]$User = 'vagrant', [string]$Password = 'vagrant', [string]$Src = (Join-Path $PSScriptRoot '..\bin'))
$ErrorActionPreference = 'Stop'
$cred = New-Object System.Management.Automation.PSCredential($User, (ConvertTo-SecureString $Password -AsPlainText -Force))
$s = New-PSSession -ComputerName 127.0.0.1 -Port $Port -Credential $cred -Authentication Negotiate
try {
  if ($Copy) {
    Invoke-Command -Session $s { New-Item -ItemType Directory -Force C:\poc41434 | Out-Null }
    Get-ChildItem (Join-Path $Src '*') -Include *.exe, *.msi | ForEach-Object { Copy-Item -ToSession $s -Path $_.FullName -Destination C:\poc41434\ -Force }
    Get-ChildItem (Join-Path $PSScriptRoot '..\scripts\*.ps1') | ForEach-Object { Copy-Item -ToSession $s -Path $_.FullName -Destination C:\poc41434\ -Force }
  }
  if ($Script) { Invoke-Command -Session $s -ScriptBlock ([scriptblock]::Create($Script)) }
} finally { Remove-PSSession $s }
