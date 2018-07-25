function backup
{
    New-Item -ItemType directory -Path .\backup -ErrorAction SilentlyContinue
    New-Item -ItemType directory -Path $env:temp\backup -ErrorAction SilentlyContinue
    Copy-Item .\* $env:temp\backup -force
    Remove-Item $env:temp\backup\backup -recurse -ErrorAction SilentlyContinue
    Copy-Item $env:temp\backup\* .\backup -force
}

function install
{
    kill -processname win32ui -ErrorAction SilentlyContinue -Force
    Remove-Item .\upgrade\upgrade_result -ErrorAction SilentlyContinue
    write-output "$(Get-Date -format u) - Start-Process." >> .\upgrade.log
    $installer = (Get-Item wazuh-agent*.msi).Basename
    $proc = Start-Process "msiexec" -ArgumentList "$('/i "' + $($installer) + '.msi" /quiet /L*V install.log')" -Passthru
    $proc.WaitForExit()
    Get-Service -Name "Wazuh" | Start-Service
}

function restore
{
    Copy-Item .\backup\* .\ -force
}


# Get current version
$current_version = (Get-Content VERSION)
$current_file_date = (Get-Item ".\ossec-agent.exe").LastWriteTime
write-output "$(Get-Date -format u) - Current version: $($current_version)" > .\upgrade.log

# Generating backup
write-output "$(Get-Date -format u) - Generating backup." >> .\upgrade.log
backup

# Ensure process is stopped before launch upgrade
Get-Service -Name "Wazuh" | Stop-Service
$process_id = (Get-Process ossec-agent -ErrorAction SilentlyContinue).id
$counter = 5
while($process_id -ne $null -And $counter -gt 0)
{
    write-output "$(Get-Date -format u) - Trying to stop Wazuh service again. Remaining attempts: $counter." >> .\upgrade.log
    $counter--
    Get-Service -Name "Wazuh" | Stop-Service
    taskkill /pid $process_id /f /T
    Start-Sleep 2
    $process_id = (Get-Process ossec-agent -ErrorAction SilentlyContinue).id
}

# Install
install
write-output "$(Get-Date -format u) - Installation in progress." >> .\upgrade.log

# Check new version
$new_version = (Get-Content VERSION)
$counter = 10
while($new_version -eq $current_version -And $counter -gt 0)
{
    write-output "$(Get-Date -format u) - Waiting for the installation end." >> .\upgrade.log
    $counter--
    Start-Sleep 2
}

# Check process status
$process_id = (Get-Process ossec-agent).id
$counter = 5
while($process_id -eq $null -And $counter -gt 0)
{
    $counter--
    Start-Service -Name "Wazuh"
    Start-Sleep 2
    $process_id = (Get-Process ossec-agent).id
}
write-output "$(Get-Date -format u) - Process ID: $($process_id)" >> .\upgrade.log

# Check status file
$status = Get-Content .\ossec-agent.state | select-string "status='connected'" -SimpleMatch
$counter = 5
while($status -eq $null -And $counter -gt 0)
{
    $counter--
    Start-Sleep 2
    $status = Get-Content .\ossec-agent.state | select-string "status='connected'" -SimpleMatch
}
write-output "$(Get-Date -format u) - Reading status file: $($status)" >> .\upgrade.log

If ($status -eq $null)
{
    write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii
    restore
    write-output "$(Get-Date -format u) - Upgrade failed: Restoring." >> .\upgrade.log
    .\ossec-agent.exe install-service >> .\upgrade.log
    Start-Service -Name "ossec-agent" -ErrorAction SilentlyContinue
}
Else
{
    write-output "0" | out-file ".\upgrade\upgrade_result" -encoding ascii
    write-output "$(Get-Date -format u) - Upgrade finished successfully." >> .\upgrade.log
    $new_version = (Get-Content VERSION)
    write-output "$(Get-Date -format u) - New version: $($new_version)" >> .\upgrade.log
}
