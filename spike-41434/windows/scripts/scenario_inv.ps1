$dir = 'C:\poc41434'; $log = "$dir\inv.txt"; $truth = "$dir\truth_inv.txt"
Remove-Item $log, $truth -ErrorAction SilentlyContinue
$p = Start-Process "$dir\invpoc.exe" -ArgumentList 60 -RedirectStandardOutput $log -PassThru -WindowStyle Hidden
Start-Sleep 3
function T($what) { "$([DateTime]::UtcNow.ToFileTimeUtc()) $what" | Out-File $truth -Append -Encoding ascii }
for ($i = 1; $i -le 3; $i++) {
  $n = "poc41434svc$i"
  T "create $n"; sc.exe create $n binPath= "C:\Windows\System32\svchost.exe -k poc" start= demand | Out-Null; Start-Sleep 2
  T "config_auto $n"; sc.exe config $n start= auto | Out-Null; Start-Sleep 2
  T "delete $n"; sc.exe delete $n | Out-Null; Start-Sleep 2
}
T "stop Spooler"; Stop-Service Spooler -Force; Start-Sleep 2
T "start Spooler"; Start-Service Spooler; Start-Sleep 2
for ($i = 1; $i -le 3; $i++) {
  $k = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Poc41434App$i"
  T "pkg_add Poc41434App$i"; New-Item $k -Force | Out-Null; New-ItemProperty $k -Name DisplayName -Value "Poc App $i" -Force | Out-Null; Start-Sleep 2
  T "pkg_del Poc41434App$i"; Remove-Item $k -Recurse -Force; Start-Sleep 2
}
$k = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Poc41434App32"
T "pkg_add32 Poc41434App32"; New-Item $k -Force | Out-Null; Start-Sleep 2
T "pkg_del32 Poc41434App32"; Remove-Item $k -Recurse -Force
$p.WaitForExit()
"INV DONE"
