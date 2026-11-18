# Exhaust the system-logger slots, check how the recommended session fails, then run plan B.
$dir = 'C:\poc41434'
"### before"; & "$dir\etwpoc.exe" list 0 | Where-Object { $_ -match 'LIST' }
$h = Start-Process "$dir\etwpoc.exe" -ArgumentList 'hog', 170, 8 -RedirectStandardOutput "$dir\hog.txt" -PassThru -WindowStyle Hidden
Start-Sleep 5
Get-Content "$dir\hog.txt"
"### during"; & "$dir\etwpoc.exe" list 0 | Where-Object { $_ -match 'LIST' }
"### recommended session (full3) with no free slot"
& "$dir\etwpoc.exe" full3 3 0 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -match 'StartTrace|READY|SUMMARY|failed' }
"### plan B"
& "$dir\scenario_ports2.ps1" -Tag planb -Mode planb | Out-Null
Get-Content "$dir\etw_planb.txt.err"
Get-Content "$dir\etw_planb.txt" | Where-Object { $_ -match '^(READY|SUMMARY|RESOURCES|TOKEN_FAIL)' }
$h.WaitForExit(); Get-Content "$dir\hog.txt" | Where-Object { $_ -match 'released' }
"### after"; & "$dir\etwpoc.exe" list 0 | Where-Object { $_ -match 'LIST' }
