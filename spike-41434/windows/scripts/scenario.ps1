param([string]$Mode = 'mp', [int]$N = 100, [int]$Secs = 40)
$ErrorActionPreference = 'Continue'
$dir = 'C:\poc41434'
$log = "$dir\etw_$Mode.txt"
$truth = "$dir\truth_$Mode.csv"
Remove-Item $log, $truth -ErrorAction SilentlyContinue
$p = Start-Process -FilePath "$dir\etwpoc.exe" -ArgumentList $Mode, $Secs, 100000 -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -WindowStyle Hidden
Start-Sleep 4
"kind,pid,exit,ms" | Out-File $truth -Encoding ascii
# 1) process storm: N short-lived cmd /c exit 3, ground truth pid + exit code
$sw = [Diagnostics.Stopwatch]::StartNew()
for ($i = 0; $i -lt $N; $i++) {
  $c = Start-Process cmd.exe -ArgumentList '/c', 'exit 3' -PassThru -WindowStyle Hidden
  $c.WaitForExit()
  "proc,$($c.Id),$($c.ExitCode),$($sw.ElapsedMilliseconds)" | Out-File $truth -Append -Encoding ascii
}
# 2) ports: TCP v4 listen <1s + connect/accept, TCP v6 listen, UDP v4 bind
$l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $l.Start(); $p4 = $l.LocalEndpoint.Port
$cl = [Net.Sockets.TcpClient]::new(); $cl.Connect("127.0.0.1", $p4); $srv = $l.AcceptTcpClient()
"tcp4_listen_connect,$PID,$p4,$($sw.ElapsedMilliseconds)" | Out-File $truth -Append -Encoding ascii
Start-Sleep -Milliseconds 300; $cl.Close(); $srv.Close(); $l.Stop()
$l6 = [Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Loopback, 0); $l6.Start(); $p6 = $l6.LocalEndpoint.Port
$c6 = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6); $c6.Connect("::1", $p6); $s6 = $l6.AcceptTcpClient()
"tcp6_listen_connect,$PID,$p6,$($sw.ElapsedMilliseconds)" | Out-File $truth -Append -Encoding ascii
Start-Sleep -Milliseconds 300; $c6.Close(); $s6.Close(); $l6.Stop()
$u = [Net.Sockets.UdpClient]::new(0); $pu = $u.Client.LocalEndPoint.Port; $u.Send([byte[]](1,2,3), 3, '127.0.0.1', 47004) | Out-Null
"udp4_bind_send,$PID,$pu,$($sw.ElapsedMilliseconds)" | Out-File $truth -Append -Encoding ascii
Start-Sleep -Milliseconds 300; $u.Close()
# 3) outbound connect to a remote host (if reachable)
try { $r = [Net.Sockets.TcpClient]::new(); $r.Connect('1.1.1.1', 443); "tcp4_remote_connect,$PID,443,$($sw.ElapsedMilliseconds)" | Out-File $truth -Append -Encoding ascii; $r.Close() } catch { "tcp4_remote_connect_failed,$PID,443,$($sw.ElapsedMilliseconds)" | Out-File $truth -Append -Encoding ascii }
$p.WaitForExit()
"DONE mode=$Mode runner_pid=$PID"
