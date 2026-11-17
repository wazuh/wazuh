Set-ExecutionPolicy -Scope Process Bypass -Force
"### decode (TDH, no print)"
& C:\poc41434\scenario_full.ps1 -Tag decode -Secs 50 -MaxPrint 0 -Decode 1 | Select-String 'RESOURCES|SUMMARY|quick'
"### idle 30 s (decode, no load)"
& C:\poc41434\etwpoc.exe full 30 0 64 64 0 1 | Select-String 'RESOURCES|SUMMARY'
"### loss: slow consumer 2 ms/event, small buffers"
& C:\poc41434\scenario_full.ps1 -Tag loss2 -Secs 70 -MaxPrint 0 -BufKb 8 -MaxBuf 4 -SlowUs 2000 | Select-String 'RESOURCES|SUMMARY|quick'
"### tamper: stop session from outside after 8 s"
$p = Start-Process C:\poc41434\etwpoc.exe -ArgumentList 'full',40,0 -RedirectStandardOutput C:\poc41434\etw_tamper.txt -PassThru -WindowStyle Hidden
Start-Sleep 8; logman stop WazuhEtwPoc41434 -ets; $p.WaitForExit()
Get-Content C:\poc41434\etw_tamper.txt | Select-String 'STOPPED|SUMMARY'
"ROUND3 DONE"
