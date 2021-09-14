# Stop UI and launch the msi installer
function install
{
    kill -processname win32ui -ErrorAction SilentlyContinue -Force
    Remove-Item .\upgrade\upgrade_result -ErrorAction SilentlyContinue
    write-output "$(Get-Date -format u) - Starting upgrade processs." >> .\upgrade\upgrade.log
    cmd /c start (Get-Item ".\wazuh-agent*.msi").Name -quiet -norestart -log installer.log
}

# Check new version and restart the Wazuh service
function check-installation
{
    $new_version = (Get-Content VERSION)
    $counter = 5
    while($new_version -eq $current_version -And $counter -gt 0)
    {
        write-output "$(Get-Date -format u) - Waiting for the installation end." >> .\upgrade\upgrade.log
        $counter--
        Start-Sleep 2
        $new_version = (Get-Content VERSION)
    }
    write-output "$(Get-Date -format u) - Restarting Wazuh service." >> .\upgrade\upgrade.log
    Get-Service -Name "Wazuh" | Start-Service
}

# Get current version
$current_version = (Get-Content VERSION)
write-output "$(Get-Date -format u) - Current version: $($current_version)" > .\upgrade\upgrade.log

# Get process name
$current_process = "wazuh-agent"
If (!(Test-Path ".\wazuh-agent.exe"))
{
    $current_process = "ossec-agent"
}

# Ensure implicated processes are stopped before launch the upgrade
Get-Process msiexec | Stop-Process -ErrorAction SilentlyContinue -Force
Get-Service -Name "Wazuh" | Stop-Service -ErrorAction SilentlyContinue -Force
$process_id = (Get-Process $current_process -ErrorAction SilentlyContinue).id
$counter = 5
while($process_id -ne $null -And $counter -gt 0)
{
    write-output "$(Get-Date -format u) - Trying to stop Wazuh service again. Remaining attempts: $counter." >> .\upgrade\upgrade.log
    $counter--
    Get-Service -Name "Wazuh" | Stop-Service
    taskkill /pid $process_id /f /T
    Start-Sleep 2
    $process_id = (Get-Process $current_process -ErrorAction SilentlyContinue).id
}

# Install
install
check-installation
write-output "$(Get-Date -format u) - Installation finished." >> .\upgrade\upgrade.log

# Check process status
$process_id = (Get-Process wazuh-agent).id
$counter = 5
while($process_id -eq $null -And $counter -gt 0)
{
    $counter--
    Start-Service -Name "Wazuh"
    Start-Sleep 2
    $process_id = (Get-Process wazuh-agent).id
}
write-output "$(Get-Date -format u) - Process ID: $($process_id)" >> .\upgrade\upgrade.log
# Wait for agent state to be cleaned
Start-Sleep 10
# Check status file
$status = Get-Content .\wazuh-agent.state | select-string "status='connected'" -SimpleMatch
$counter = 5
while($status -eq $null -And $counter -gt 0)
{
    $counter--
    Start-Sleep 2
    $status = Get-Content .\wazuh-agent.state | select-string "status='connected'" -SimpleMatch
}
write-output "$(Get-Date -format u) - Reading status file: $($status)" >> .\upgrade\upgrade.log

If ($status -eq $null)
{
    write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii
    write-output "$(Get-Date -format u) - Upgrade failed. Agent installation may be broken." >> .\upgrade\upgrade.log
}
Else
{
    write-output "0" | out-file ".\upgrade\upgrade_result" -encoding ascii
    write-output "$(Get-Date -format u) - Upgrade finished successfully." >> .\upgrade\upgrade.log
    $new_version = (Get-Content VERSION)
    write-output "$(Get-Date -format u) - New version: $($new_version)" >> .\upgrade\upgrade.log
}

Remove-Item -Path ".\upgrade\*"  -Exclude "*.log", "upgrade_result" -ErrorAction SilentlyContinue
