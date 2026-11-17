param([int]$Secs = 25)
$dir = 'C:\poc41434'; $log = "$dir\etw_afd.txt"; $truth = "$dir\truth_afd.csv"
Remove-Item $log, $truth -ErrorAction SilentlyContinue
$p = Start-Process -FilePath "$dir\etwpoc.exe" -ArgumentList 'afd', $Secs, 100000 -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -WindowStyle Hidden
Start-Sleep 4
"kind,pid,port" | Out-File $truth -Encoding ascii
# listener that NEVER gets a connection, open 2 s
$l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, 0); $l.Start(); $lp = $l.LocalEndpoint.Port
"tcp4_listen_only,$PID,$lp" | Out-File $truth -Append -Encoding ascii
Start-Sleep 2; $l.Stop()
# quick listener, 300 ms, IPv6
$l6 = [Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Any, 0); $l6.Start(); $lp6 = $l6.LocalEndpoint.Port
"tcp6_listen_only,$PID,$lp6" | Out-File $truth -Append -Encoding ascii
Start-Sleep -Milliseconds 300; $l6.Stop()
# UDP bind with no traffic
$u = [Net.Sockets.UdpClient]::new(0); $up = $u.Client.LocalEndPoint.Port
"udp4_bind_only,$PID,$up" | Out-File $truth -Append -Encoding ascii
Start-Sleep 1; $u.Close()
$p.WaitForExit()
"DONE runner_pid=$PID"
