# Sustained load: CPU burners + a steady stream of short processes, consumer decoding without printing.
param([int]$Burners = 1, [int]$FlushMs = 0, [string]$Tag = 'load', [int]$Secs = 150)
$dir = 'C:\poc41434'; $log = "$dir\etw_$Tag.txt"
$p = Start-Process "$dir\etwpoc.exe" -ArgumentList 'full3', $Secs, 0, 64, 64, 0, 1, $FlushMs, 0 -RedirectStandardOutput $log -PassThru -WindowStyle Hidden
Start-Sleep 4
$burn = 1..$Burners | ForEach-Object { Start-Process powershell.exe -ArgumentList '-NoProfile', '-Command', "`$e=(Get-Date).AddSeconds($($Secs - 20)); while((Get-Date) -lt `$e){}" -PassThru -WindowStyle Hidden }
$sw = [Diagnostics.Stopwatch]::StartNew(); $n = 0
while ($sw.Elapsed.TotalSeconds -lt ($Secs - 25)) { & "$dir\quick.exe"; $n++; Start-Sleep -Milliseconds 40 }
"LOAD burners=$Burners launched=$n in $([int]$sw.Elapsed.TotalSeconds) s flush_ms=$FlushMs"
$burn | ForEach-Object { $_.WaitForExit() }
$p.WaitForExit()
Get-Content $log | Select-String '^(RESOURCES|SUMMARY)' | ForEach-Object { $_.Line }
