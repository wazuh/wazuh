param([int]$Secs = 170, [switch]$NetworkTest)
$dir = 'C:\poc41434'; $log = "$dir\inv2.txt"; $truth = "$dir\truth_inv2.txt"
Remove-Item $log, $truth -ErrorAction SilentlyContinue
"AUDITPOL"; auditpol /get /subcategory:"User Account Management","Security Group Management"
$p = Start-Process "$dir\invpoc.exe" -ArgumentList $Secs -RedirectStandardOutput $log -PassThru -WindowStyle Hidden
Start-Sleep 4
function T($what) { "$([DateTime]::UtcNow.ToFileTimeUtc()) $what" | Out-File $truth -Append -Encoding ascii }
# real MSI, machine-wide
T 'msi_install 7zip'; $r = Start-Process msiexec.exe -ArgumentList '/i', "$dir\7z-x64.msi", '/qn', '/norestart' -Wait -PassThru; T "msi_install_done rc=$($r.ExitCode)"; Start-Sleep 3
T 'msi_uninstall 7zip'; $r = Start-Process msiexec.exe -ArgumentList '/x', "$dir\7z-x64.msi", '/qn', '/norestart' -Wait -PassThru; T "msi_uninstall_done rc=$($r.ExitCode)"; Start-Sleep 3
# per-user Uninstall key (HKCU of this session = HKU\<SID>)
$k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Poc41434User'
T 'hku_add Poc41434User'; New-Item $k -Force | Out-Null; New-ItemProperty $k -Name DisplayName -Value 'Poc User App' -Force | Out-Null; Start-Sleep 3
T 'hku_del Poc41434User'; Remove-Item $k -Recurse -Force; Start-Sleep 3
# AppX: remove and re-register a provisioned package for this user
$pkg = Get-AppxPackage -Name Microsoft.WindowsCalculator -ErrorAction SilentlyContinue
$prov = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object DisplayName -eq 'Microsoft.WindowsCalculator'
if ($pkg -and $prov) {
  $man = Join-Path $pkg.InstallLocation 'AppxManifest.xml'
  T "appx_remove $($pkg.PackageFullName)"; try { Remove-AppxPackage $pkg.PackageFullName -ErrorAction Stop; T 'appx_remove_done' } catch { T "appx_remove_failed $($_.Exception.HResult)" }; Start-Sleep 5
  T 'appx_add'; try { Add-AppxPackage -Register $man -DisableDevelopmentMode -ErrorAction Stop; T 'appx_add_done' } catch { T "appx_add_failed $($_.Exception.HResult)" }; Start-Sleep 5
  "APPX after: $((Get-AppxPackage -Name Microsoft.WindowsCalculator).PackageFullName)"
} else { T "appx_skipped pkg=$([bool]$pkg) prov=$([bool]$prov)" }
# users and local groups
T 'user_add poc41434u'; net user poc41434u 'Pz-41434-xQ!' /add | Out-Null; Start-Sleep 3
T 'group_add Users'; net localgroup Users poc41434u /delete | Out-Null; Start-Sleep 1; net localgroup Users poc41434u /add | Out-Null; Start-Sleep 3
T 'group_del Users'; net localgroup Users poc41434u /delete | Out-Null; Start-Sleep 3
T 'user_del poc41434u'; net user poc41434u /delete | Out-Null; Start-Sleep 3
# network: secondary address and MTU change on the default-route interface.
# Disposable VMs only: New-NetIPAddress on a DHCP interface disables DHCP, and removing the address leaves it with no lease.
if ($NetworkTest) {
  $if = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex
  $mtu = (Get-NetIPInterface -InterfaceIndex $if -AddressFamily IPv4).NlMtu
  T "addr_add if=$if"; New-NetIPAddress -InterfaceIndex $if -IPAddress 10.254.254.254 -PrefixLength 32 -SkipAsSource $true | Out-Null; Start-Sleep 3
  T "addr_del if=$if"; Remove-NetIPAddress -InterfaceIndex $if -IPAddress 10.254.254.254 -Confirm:$false; Start-Sleep 3
  T "mtu_set 1400 if=$if"; Set-NetIPInterface -InterfaceIndex $if -AddressFamily IPv4 -NlMtuBytes 1400; Start-Sleep 3
  T "mtu_restore $mtu if=$if"; Set-NetIPInterface -InterfaceIndex $if -AddressFamily IPv4 -NlMtuBytes $mtu; Start-Sleep 3
}
$p.WaitForExit()
"INV2 DONE"
