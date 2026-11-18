# WMI process traces as a fallback: coverage and cost for the same storm.
$dir = 'C:\poc41434'
$cpu0 = (Get-Process WmiPrvSE -ErrorAction SilentlyContinue | Measure-Object CPU -Sum).Sum
Register-CimIndicationEvent -ClassName Win32_ProcessStartTrace -SourceIdentifier pstart
Register-CimIndicationEvent -ClassName Win32_ProcessStopTrace -SourceIdentifier pstop
Start-Sleep 3
$sw = [Diagnostics.Stopwatch]::StartNew()
cmd /c "for /L %i in (1,1,200) do @$dir\quick.exe"
$jobs = 1..2 | ForEach-Object { Start-Process cmd.exe -ArgumentList '/c', "for /L %i in (1,1,100) do @$dir\quick.exe" -PassThru -WindowStyle Hidden }
$jobs | ForEach-Object { $_.WaitForExit() }
"storm 400 in $($sw.ElapsedMilliseconds) ms"
Start-Sleep 15
$s = @(Get-Event -SourceIdentifier pstart -ErrorAction SilentlyContinue | Where-Object { $_.SourceEventArgs.NewEvent.ProcessName -eq 'quick.exe' })
$e = @(Get-Event -SourceIdentifier pstop -ErrorAction SilentlyContinue | Where-Object { $_.SourceEventArgs.NewEvent.ProcessName -eq 'quick.exe' })
$cpu1 = (Get-Process WmiPrvSE -ErrorAction SilentlyContinue | Measure-Object CPU -Sum).Sum
"WMI starts=$($s.Count) stops=$($e.Count) exit7=$(@($e | Where-Object { $_.SourceEventArgs.NewEvent.ExitStatus -eq 7 }).Count)"
if ($s.Count) { $n = $s[0].SourceEventArgs.NewEvent; "start fields: " + (($n.CimInstanceProperties | ForEach-Object { $_.Name }) -join ',') }
$lat = $s | ForEach-Object { ($_.TimeGenerated - [DateTime]::FromFileTime([long]$_.SourceEventArgs.NewEvent.TIME_CREATED)).TotalMilliseconds } | Sort-Object
if ($lat) { "latency ms p50=$([int]$lat[[int]($lat.Count/2)]) max=$([int]$lat[-1])" }
"WmiPrvSE cpu_s delta=$([math]::Round($cpu1 - $cpu0, 2))"
Unregister-Event pstart; Unregister-Event pstop
