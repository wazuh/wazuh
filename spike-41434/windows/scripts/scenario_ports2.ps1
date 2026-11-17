param([string]$Tag = 'p2', [int]$Secs = 75, [int]$FlushMs = 0, [int]$Seq = 100, [int]$Par = 2, [int]$PerPar = 50)
$dir = 'C:\poc41434'; $log = "$dir\etw_$Tag.txt"; $truth = "$dir\truth_$Tag.csv"; $sys = "$dir\sys_$Tag.txt"
Remove-Item $log, $truth, $sys -ErrorAction SilentlyContinue
$p = Start-Process -FilePath "$dir\etwpoc.exe" -ArgumentList 'full3', $Secs, 1000000, 64, 64, 0, 0, $FlushMs, 0 -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -WindowStyle Hidden
Start-Sleep 4
"kind,count,detail" | Out-File $truth -Encoding ascii
function T($k, $c, $d) { "$k,$c,$d" | Out-File $truth -Append -Encoding ascii }
$sw = [Diagnostics.Stopwatch]::StartNew()
cmd /c "for /L %i in (1,1,$Seq) do @$dir\quick.exe"
T 'seq_quick' $Seq "$($sw.ElapsedMilliseconds)ms"
$jobs = 1..$Par | ForEach-Object { Start-Process cmd.exe -ArgumentList '/c', "for /L %i in (1,1,$PerPar) do @$dir\quick.exe" -PassThru -WindowStyle Hidden }
$jobs | ForEach-Object { $_.WaitForExit() }
T 'par_quick' ($Par * $PerPar) "$($sw.ElapsedMilliseconds)ms"
# fast ports: open for 300 ms, no traffic, TCP/UDP x IPv4/IPv6, 3 rounds
for ($i = 1; $i -le 3; $i++) {
  $l4 = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any, 0); $l4.Start()
  $l6 = New-Object Net.Sockets.TcpListener([Net.IPAddress]::IPv6Any, 0); $l6.Start()
  $u4 = New-Object Net.Sockets.UdpClient(0, [Net.Sockets.AddressFamily]::InterNetwork)
  $u6 = New-Object Net.Sockets.UdpClient(0, [Net.Sockets.AddressFamily]::InterNetworkV6)
  T 'tcp4_listen' 1 "$PID/$($l4.LocalEndpoint.Port)"; T 'tcp6_listen' 1 "$PID/$($l6.LocalEndpoint.Port)"
  T 'udp4_bind' 1 "$PID/$($u4.Client.LocalEndPoint.Port)"; T 'udp6_bind' 1 "$PID/$($u6.Client.LocalEndPoint.Port)"
  Start-Sleep -Milliseconds 300
  $l4.Stop(); $l6.Stop(); $u4.Close(); $u6.Close()
}
# connect/accept
$l = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any, 0); $l.Start(); $cc = New-Object Net.Sockets.TcpClient; $cc.Connect('127.0.0.1', $l.LocalEndpoint.Port); $sv = $l.AcceptTcpClient()
T 'connect' 1 "$PID/$($l.LocalEndpoint.Port)"; Start-Sleep 1; $cc.Close(); $sv.Close(); $l.Stop()
# as SYSTEM (scheduled task running a script file; wait up to 90 s for it)
$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File $dir\sys_part.ps1 -Out $sys"
Register-ScheduledTask -TaskName poc41434 -Action $a -User "SYSTEM" -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) -Force | Out-Null
Start-ScheduledTask -TaskName poc41434
for ($w = 0; $w -lt 90 -and -not (Test-Path $sys); $w++) { Start-Sleep 1 }
Start-Sleep 3; Unregister-ScheduledTask -TaskName poc41434 -Confirm:$false
if (Test-Path $sys) { $s = (Get-Content $sys).Trim().Split(','); T 'system_quick' 5 "$($s[0])"; T 'tcp4_listen_system' 1 "$($s[0])/$($s[1])"; T 'udp6_bind_system' 1 "$($s[0])/$($s[2])" } else { T 'system_missing' 0 "waited ${w}s" }
$p.WaitForExit()
Get-Content "$log.err"
Get-Content $log | Select-String '^(RESOURCES|SUMMARY|READY)'
Get-Content $truth
