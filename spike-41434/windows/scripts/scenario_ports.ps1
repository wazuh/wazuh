param([int]$Secs = 30)
$dir = 'C:\poc41434'; $log = "$dir\etw_ports.txt"; $truth = "$dir\truth_ports.csv"
Remove-Item $log, $truth, "$dir\sys_port.txt" -ErrorAction SilentlyContinue
$p = Start-Process -FilePath "$dir\etwpoc.exe" -ArgumentList 'ports', $Secs, 100000 -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -WindowStyle Hidden
Start-Sleep 4
"kind,pid,port" | Out-File $truth -Encoding ascii
$l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, 0); $l.Start(); "tcp4_listen_vagrant,$PID,$($l.LocalEndpoint.Port)" | Out-File $truth -Append -Encoding ascii; Start-Sleep 1; $l.Stop()
$u = [Net.Sockets.UdpClient]::new(0); "udp4_bind_vagrant,$PID,$($u.Client.LocalEndPoint.Port)" | Out-File $truth -Append -Encoding ascii; Start-Sleep 1; $u.Close()
# same listener as SYSTEM through a one-shot scheduled task
$cmd = '$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Any,0);$l.Start();"$PID,$($l.LocalEndpoint.Port)"|Out-File C:\poc41434\sys_port.txt -Encoding ascii;Start-Sleep 2;$l.Stop()'
$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -Command $cmd"
Register-ScheduledTask -TaskName poc41434 -Action $a -User 'SYSTEM' -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) -Force | Out-Null
Start-ScheduledTask -TaskName poc41434; Start-Sleep 8; Unregister-ScheduledTask -TaskName poc41434 -Confirm:$false
if (Test-Path "$dir\sys_port.txt") { "tcp4_listen_system,$((Get-Content $dir\sys_port.txt).Trim())" | Out-File $truth -Append -Encoding ascii }
$p.WaitForExit()
"DONE"
