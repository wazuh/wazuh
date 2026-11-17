$d = 'C:\poc41434'
Remove-Item "$d\etw_loss3.txt" -ErrorAction SilentlyContinue
$p = Start-Process "$d\etwpoc.exe" -ArgumentList 'full2', 90, 0, 4, 2, 5000 -RedirectStandardOutput "$d\etw_loss3.txt" -PassThru -WindowStyle Hidden
Start-Sleep 4
$sw = [Diagnostics.Stopwatch]::StartNew()
$jobs = 1..8 | ForEach-Object { Start-Process cmd.exe -ArgumentList '/c', "for /L %i in (1,1,300) do @$d\quick.exe" -PassThru -WindowStyle Hidden }
$jobs | ForEach-Object { $_.WaitForExit() }
"storm 2400 quick.exe in $($sw.ElapsedMilliseconds) ms"
$p.WaitForExit()
Get-Content "$d\etw_loss3.txt" | Where-Object { $_ -match 'SUMMARY|RESOURCES' }
"LOSS DONE"
