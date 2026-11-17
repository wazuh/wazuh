$dir = 'C:\poc41434'; $log = "$dir\etw_udpprobe.txt"; $truth = "$dir\truth_udpprobe.csv"
Remove-Item $log, $truth -ErrorAction SilentlyContinue
$p = Start-Process -FilePath "$dir\etwpoc.exe" -ArgumentList 'afd', 20, 1000000 -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -WindowStyle Hidden
Start-Sleep 4
"kind,count,detail" | Out-File $truth -Encoding ascii
for ($i = 1; $i -le 2; $i++) {
  $u4 = New-Object Net.Sockets.UdpClient(0, [Net.Sockets.AddressFamily]::InterNetwork)
  $u6 = New-Object Net.Sockets.UdpClient(0, [Net.Sockets.AddressFamily]::InterNetworkV6)
  "udp4_bind,1,$PID/$($u4.Client.LocalEndPoint.Port)" | Out-File $truth -Append -Encoding ascii
  "udp6_bind,1,$PID/$($u6.Client.LocalEndPoint.Port)" | Out-File $truth -Append -Encoding ascii
  Start-Sleep -Milliseconds 300; $u4.Close(); $u6.Close()
}
$p.WaitForExit()
Get-Content $truth
