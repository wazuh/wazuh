$t0 = Get-Date
auditpol /get /subcategory:"User Account Management","Security Group Management"
net user poc41434u 'Pz-41434-xQ!' /add | Out-Null
net localgroup Users poc41434u /delete 2>$null | Out-Null
net localgroup Users poc41434u /add | Out-Null
net localgroup Users poc41434u /delete | Out-Null
net user poc41434u /delete | Out-Null
Start-Sleep 2
$ev = Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4720, 4726, 4732, 4733; StartTime = $t0} -ErrorAction SilentlyContinue
"AUDIT_EVENTS " + (($ev | Group-Object Id | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' ')
