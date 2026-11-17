$d = 'C:\poc41434'

$t0 = Get-Date
1..5 | ForEach-Object { & "$d\quick.exe" }
$l = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any, 0); $l.Start(); $p = $l.LocalEndpoint.Port
$c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', $p); $s = $l.AcceptTcpClient(); Start-Sleep 1; $c.Close(); $s.Close(); $l.Stop()
"TRUTH listen_port=$p runner_pid=$PID quick=5 exit=7"
Start-Sleep 5
$ev = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 400 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $t0 }
"counts: " + (($ev | Group-Object Id | ForEach-Object { "id$($_.Name)=$($_.Count)" }) -join ' ')
foreach ($id in 1,5,3) {
  $e = $ev | Where-Object { $_.Id -eq $id -and ($_.Message -match 'quick.exe' -or $_.Message -match "$p") } | Select-Object -First 1
  "=== Sysmon event $id fields:"; if ($e) { ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { "  $($_.Name)=$($_.'#text')" } } else { "  (none)" }
}
"listen/bind event present? " + [bool]($ev | Where-Object { $_.Message -match "SourcePort: $p" -and $_.Id -eq 3 -and $_.Message -match 'Initiated: false' })
"SYSMON DONE"
