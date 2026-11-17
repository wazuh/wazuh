param([string]$Tag = 'wd', [int]$N = 300)
$dir = 'C:\poc41434'; $log = "$dir\etw_$Tag.txt"; $truth = "$dir\truth_$Tag.csv"
Remove-Item $log, $truth -ErrorAction SilentlyContinue
$p = Start-Process -FilePath "$dir\etwpoc.exe" -ArgumentList 'full3', 60, 1000000, 64, 64, 0, 0, 0, 1 -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -WindowStyle Hidden
Start-Sleep 4
"i,utc_ft" | Out-File $truth -Encoding ascii
$sw = [Diagnostics.Stopwatch]::StartNew(); $stopped = $false
for ($i = 1; $i -le $N; $i++) {
  if (-not $stopped -and $sw.ElapsedMilliseconds -gt 8000) { "STOP,$([DateTime]::UtcNow.ToFileTimeUtc())" | Out-File $truth -Append -Encoding ascii; logman stop WazuhEtwPoc41434 -ets | Out-Null; $stopped = $true }
  "$i,$([DateTime]::UtcNow.ToFileTimeUtc())" | Out-File $truth -Append -Encoding ascii
  & "$dir\quick.exe"; Start-Sleep -Milliseconds 50
}
"END,$([DateTime]::UtcNow.ToFileTimeUtc())" | Out-File $truth -Append -Encoding ascii
$p.WaitForExit()
Get-Content $log | Select-String '^(RESOURCES|SUMMARY|READY|SESSION_)'
