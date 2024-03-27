# Finding MSI useful constants
$Env:WAZUH_DEF_REG_START_PATH = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\"
$Env:WAZUH_PUBLISHER_VALUE    = "Wazuh, Inc."

# Check if there is an upgrade in progress
if (Test-Path ".\upgrade\upgrade_in_progress") {
    write-output "$(Get-Date -format u) - There is an upgrade in progress. Aborting..." >> .\upgrade\upgrade.log
    exit 1
}

# Delete previous upgrade.log
Remove-Item -Path ".\upgrade\upgrade.log" -ErrorAction SilentlyContinue

# Select powershell
if (Test-Path "$env:windir\sysnative") {
    write-output "$(Get-Date -format u) - Sysnative Powershell will be used to access the registry." >> .\upgrade\upgrade.log
    Set-Alias Start-NativePowerShell "$env:windir\sysnative\WindowsPowerShell\v1.0\powershell.exe"
} else {
    Set-Alias Start-NativePowerShell "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
}

# Check new version and restart the Wazuh service
function check-installation
{
    $new_version = (Get-Content VERSION)
    $counter = 5
    while($new_version -eq $current_version -And $counter -gt 0)
    {
        write-output "$(Get-Date -format u) - Waiting for the Wazuh-Agent installation to end." >> .\upgrade\upgrade.log
        $counter--
        Start-Sleep 2
        $new_version = (Get-Content VERSION)
    }
    write-output "$(Get-Date -format u) - Restarting Wazuh-Agent service." >> .\upgrade\upgrade.log
    Get-Service -Name "Wazuh" | Start-Service
}

# Stop UI and launch the msi installer
function install
{
    kill -processname win32ui -ErrorAction SilentlyContinue -Force
    Remove-Item .\upgrade\upgrade_result -ErrorAction SilentlyContinue
    write-output "$(Get-Date -format u) - Starting upgrade processs." >> .\upgrade\upgrade.log
    cmd /c start /wait (Get-Item ".\wazuh-agent*.msi").Name -quiet -norestart -log installer.log
}

write-output "0" | out-file ".\upgrade\upgrade_in_progress" -encoding ascii

# Get current version
$current_version = (Get-Content VERSION)
write-output "$(Get-Date -format u) - Current version: $($current_version)." >> .\upgrade\upgrade.log

# Get process name
$current_process = "wazuh-agent"
If (!(Test-Path ".\wazuh-agent.exe"))
{
    $current_process = "ossec-agent"
}

# Ensure no other instance of msiexec is running by stopping them
Get-Process msiexec | Stop-Process -ErrorAction SilentlyContinue -Force

# Install
install
check-installation
write-output "$(Get-Date -format u) - Installation finished." >> .\upgrade\upgrade.log

# Check process status
$process_id = (Get-Process wazuh-agent).id
$counter = 10
while($process_id -eq $null -And $counter -gt 0)
{
    $counter--
    Start-Service -Name "Wazuh"
    Start-Sleep 2
    $process_id = (Get-Process wazuh-agent).id
}
write-output "$(Get-Date -format u) - Process ID: $($process_id)." >> .\upgrade\upgrade.log

# Wait for agent state to be cleaned
Start-Sleep 10

# Check status file
function Get-AgentStatus {
    Select-String -Path '.\wazuh-agent.state' -Pattern "^status='(.+)'" | %{$_.Matches[0].Groups[1].value}
}

$status = Get-AgentStatus
$counter = 30
while($status -ne "connected"  -And $counter -gt 0)
{
    $counter--
    Start-Sleep 2
    $status = Get-AgentStatus
}
Write-Output "$(Get-Date -Format u) - Reading status file: status='$status'." >> .\upgrade\upgrade.log

If ($status -ne "connected")
{
    write-output "$(Get-Date -format u) - Upgrade failed." >> .\upgrade\upgrade.log
    write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii
}
Else
{
    write-output "0" | out-file ".\upgrade\upgrade_result" -encoding ascii
    write-output "$(Get-Date -format u) - Upgrade finished successfully." >> .\upgrade\upgrade.log
    $new_version = (Get-Content VERSION)
    write-output "$(Get-Date -format u) - New version: $($new_version)." >> .\upgrade\upgrade.log
}

Remove-Item -Path ".\upgrade\*"  -Exclude "*.log", "upgrade_result" -ErrorAction SilentlyContinue
Remove-Item -Path ".\wazuh-agent*.msi" -ErrorAction SilentlyContinue
Remove-Item -Path ".\do_upgrade.ps1" -ErrorAction SilentlyContinue

exit 0
