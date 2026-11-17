param([string]$Out)
$dir = 'C:\poc41434'
1..5 | ForEach-Object { & "$dir\quick.exe" }
$l = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any, 0); $l.Start()
$u = New-Object Net.Sockets.UdpClient(0, [Net.Sockets.AddressFamily]::InterNetworkV6)
"$PID,$($l.LocalEndpoint.Port),$($u.Client.LocalEndPoint.Port)" | Out-File $Out -Encoding ascii
Start-Sleep -Milliseconds 300
$l.Stop(); $u.Close()
