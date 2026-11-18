# Install Sysmon (events 1, 3, 5), run the ports2 scenario next to it, check both saw the processes, uninstall.
$dir = 'C:\poc41434'
'<Sysmon schemaversion="4.90"><EventFiltering><ProcessCreate onmatch="exclude" /><ProcessTerminate onmatch="exclude" /><NetworkConnect onmatch="exclude" /></EventFiltering></Sysmon>' | Out-File "$dir\sysmon41434.xml" -Encoding ascii
& "$dir\Sysmon64.exe" -accepteula -i "$dir\sysmon41434.xml" 2>&1 | Select-String -Pattern 'started|installed|rror' | ForEach-Object { "$_" }
Get-Service Sysmon64 -ErrorAction SilentlyContinue | ForEach-Object { "SERVICE $($_.Name) $($_.Status)" }
& "$dir\etwpoc.exe" list 0 | Where-Object { $_ -match 'LIST' }
$t0 = Get-Date
& "$dir\scenario_ports2.ps1" -Tag coexist | Out-Null
Start-Sleep 5
$ev = Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1, 5; StartTime = $t0} -ErrorAction SilentlyContinue
"SYSMON quick.exe id1=$(@($ev | Where-Object { $_.Id -eq 1 -and $_.Message -match 'quick.exe' }).Count) id5=$(@($ev | Where-Object { $_.Id -eq 5 -and $_.Message -match 'quick.exe' }).Count)"
& "$dir\Sysmon64.exe" -u 2>&1 | Select-String -Pattern 'removed|stopped|rror' | ForEach-Object { "$_" }
Get-Service Sysmon64 -ErrorAction SilentlyContinue | ForEach-Object { "SERVICE_AFTER $($_.Name) $($_.Status)" }
