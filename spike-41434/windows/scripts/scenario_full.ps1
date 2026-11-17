param([string]$Tag = 'full', [string]$Mode = 'full', [int]$Secs = 60, [int]$MaxPrint = 1000000, [int]$BufKb = 64, [int]$MaxBuf = 64, [int]$SlowUs = 0, [int]$Decode = 0, [int]$FlushMs = 0, [int]$Seq = 500, [int]$Par = 4, [int]$PerPar = 250)
$dir = 'C:\poc41434'; $log = "$dir\etw_$Tag.txt"; $truth = "$dir\truth_$Tag.csv"
Remove-Item $log, $truth, "$dir\sys_$Tag.txt" -ErrorAction SilentlyContinue
$p = Start-Process -FilePath "$dir\etwpoc.exe" -ArgumentList $Mode, $Secs, $MaxPrint, $BufKb, $MaxBuf, $SlowUs, $Decode, $FlushMs, 0 -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -WindowStyle Hidden
Start-Sleep 4
"kind,count,detail" | Out-File $truth -Encoding ascii
$sw = [Diagnostics.Stopwatch]::StartNew()
# sequential storm of a <10 ms process (quick.exe returns 7)
cmd /c "for /L %i in (1,1,$Seq) do @$dir\quick.exe"
"seq_quick,$Seq,$($sw.ElapsedMilliseconds)ms" | Out-File $truth -Append -Encoding ascii
# parallel storm
$jobs = 1..$Par | ForEach-Object { Start-Process cmd.exe -ArgumentList '/c', "for /L %i in (1,1,$PerPar) do @$dir\quick.exe" -PassThru -WindowStyle Hidden }
$jobs | ForEach-Object { $_.WaitForExit() }
"par_quick,$($Par*$PerPar),$($sw.ElapsedMilliseconds)ms" | Out-File $truth -Append -Encoding ascii
# listener as vagrant
$l = (New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any, 0)); $l.Start(); "listen_vagrant,1,$PID/$($l.LocalEndpoint.Port)" | Out-File $truth -Append -Encoding ascii; $cc = (New-Object Net.Sockets.TcpClient); $cc.Connect("127.0.0.1", $l.LocalEndpoint.Port); $sv = $l.AcceptTcpClient(); "connect_vagrant,1,$($l.LocalEndpoint.Port)" | Out-File $truth -Append -Encoding ascii; Start-Sleep 1; $cc.Close(); $sv.Close(); $l.Stop()
# as SYSTEM: 5 quick.exe + a listener
$cmd = "1..5 | % { & $dir\quick.exe }; `$l=(New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any,0));`$l.Start();('{0}/{1}' -f `$PID,`$l.LocalEndpoint.Port)|Out-File $dir\sys_$Tag.txt -Encoding ascii;Start-Sleep 2;`$l.Stop()"
$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -Command $cmd"
Register-ScheduledTask -TaskName poc41434 -Action $a -User 'SYSTEM' -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) -Force | Out-Null
Start-ScheduledTask -TaskName poc41434; Start-Sleep 10; Unregister-ScheduledTask -TaskName poc41434 -Confirm:$false
if (Test-Path "$dir\sys_$Tag.txt") { "listen_system,1,$((Get-Content $dir\sys_$Tag.txt).Trim())" | Out-File $truth -Append -Encoding ascii }
$p.WaitForExit()
Get-Content "$log.err"
Get-Content $log | Select-String '^(RESOURCES|SUMMARY|READY)'
Get-Content $truth
