# Backup dirs
$Env:WAZUH_BACKUP_DIR         = ".\backup"
$TMP_BACKUP_DIR               = "wazuh_backup_tmp"
# Finding MSI useful constants
$Env:WAZUH_DEF_REG_START_PATH = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\"
$Env:WAZUH_PUBLISHER_VALUE    = "Wazuh, Inc."

# Select powershell
if ([Environment]::Is64BitOperatingSystem) {
    Set-Alias Start-NativePowerShell "$env:windir\sysnative\WindowsPowerShell\v1.0\powershell.exe"
} else {
    Set-Alias Start-NativePowerShell "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
}

function backup_home
{
    write-output "$(Get-Date -format u) - Backing up Wazuh home files." >> .\upgrade\upgrade.log
    # Clean before backup
    Remove-Item $Env:WAZUH_BACKUP_DIR -recurse -ErrorAction SilentlyContinue -force
    Remove-Item $env:temp\$TMP_BACKUP_DIR -recurse -ErrorAction SilentlyContinue

    # Save wazuh home in tmp dir (Exclude not filter directories)
    New-Item -ItemType directory -Path $env:temp\$TMP_BACKUP_DIR -ErrorAction SilentlyContinue
    Copy-Item .\*  $env:temp\$TMP_BACKUP_DIR -force

    # Move the tmp dir to local dir
    New-Item -ItemType directory -Path $Env:WAZUH_BACKUP_DIR -ErrorAction SilentlyContinue
    Copy-Item $env:temp\$TMP_BACKUP_DIR\* $Env:WAZUH_BACKUP_DIR -force
    Remove-Item $env:temp\$TMP_BACKUP_DIR -recurse -ErrorAction SilentlyContinue

}

function backup_msi {

    Start-NativePowerShell {

        write-output "$(Get-Date -format u) - Searching Wazuh-Agent MSI on the registry." >> .\upgrade\upgrade.log

        $path = Get-ChildItem $Env:WAZUH_DEF_REG_START_PATH
        $wazuh_msi_path = $null

        # Searching through the registry keys (Starting from $WAZUH_DEF_REG_START_PATH)
        foreach ($subpaths in $path) {
            $subpath = $subpaths | Get-ChildItem
            foreach ($subsubpath in $subpath) {
                if ($subsubpath -match "InstallProperties") {
                    if ($subsubpath.GetValue("Publisher") -match $Env:WAZUH_PUBLISHER_VALUE) {
                        $wazuh_msi_path = $subsubpath.GetValue("LocalPackage")
                    }
                }
            }
        }

        # Do backup the MSI if it exists
        if ($wazuh_msi_path -ne $null) {
            $msi_filename = Split-Path $wazuh_msi_path -leaf
            write-output "$(Get-Date -format u) - Backing up Wazuh-Agent MSI: `"$wazuh_msi_path`"." >> .\upgrade\upgrade.log
            Copy-Item $wazuh_msi_path -Destination $Env:WAZUH_BACKUP_DIR -force
            Write-Output "$msi_filename"
        } else {
            write-output "$(Get-Date -format u) - Wazuh-Agent MSI was not found." >> .\upgrade\upgrade.log
        }
    }
}

# Looks for the Wazuh-Agent uninstall command and executes it, if exists
function uninstall_wazuh {

    Start-NativePowerShell {

        $UninstallString = $null
        # Searching through the registry keys (Starting from $WAZUH_DEF_REG_START_PATH)
        $path = Get-ChildItem $Env:WAZUH_DEF_REG_START_PATH
        foreach ($subpaths in $path) {
            $subpath = $subpaths | Get-ChildItem
            foreach ($subsubpath in $subpath) {
                if ($subsubpath -match "InstallProperties") {
                    if ($subsubpath.GetValue("Publisher") -match $Env:WAZUH_PUBLISHER_VALUE) {
                        $UninstallString = $subsubpath.GetValue("UninstallString") + " /quiet /norestart"
                    }
                }
            }
        }

        if ($UninstallString -ne $null) {
            write-output "$(Get-Date -format u) - Performing the Wazuh-Agent uninstall using: `"$UninstallString`"." >> .\upgrade\upgrade.log
            & "C:\Windows\SYSTEM32\cmd.exe" /c $UninstallString
        } else {
            write-output "$(Get-Date -format u) - Wazuh-Agent uninstall command was not found." >> .\upgrade\upgrade.log
        }
    }
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

function restore
{
    param (
        $msi_filename
    )

    kill -processname win32ui -ErrorAction SilentlyContinue -Force

    # Saves ossec.log before remove fail update
    Copy-Item $Env:WAZUH_BACKUP_DIR\ossec.log $Env:WAZUH_BACKUP_DIR\ossec.log.save -force
    Copy-Item ossec.log $Env:WAZUH_BACKUP_DIR\ossec.log -force

    uninstall_wazuh

    if ($msi_filename -ne $null) {
        write-output "$(Get-Date -format u) - Excecuting former Wazuh-Agent MSI: `"$Env:WAZUH_BACKUP_DIR\$msi_filename`"." >> .\upgrade\upgrade.log
        cmd /c start $Env:WAZUH_BACKUP_DIR\$msi_filename -quiet -norestart -log installer.log
    }

    # Restore old files
    write-output "$(Get-Date -format u) - Restoring former Wazuh-Agent home files." >> .\upgrade\upgrade.log
    Copy-Item $Env:WAZUH_BACKUP_DIR\* .\ -force

    # Get current version
    $current_version = (Get-Content VERSION)
    write-output "$(Get-Date -format u) - Current version: $($current_version)" >> .\upgrade\upgrade.log
    check-installation
    Get-Service -Name "Wazuh" | Start-Service
}


# Stop UI and launch the msi installer
function install
{
    kill -processname win32ui -ErrorAction SilentlyContinue -Force
    Remove-Item .\upgrade\upgrade_result -ErrorAction SilentlyContinue
    write-output "$(Get-Date -format u) - Starting upgrade processs." >> .\upgrade\upgrade.log
    cmd /c start (Get-Item ".\wazuh-agent*.msi").Name -quiet -norestart -log installer.log
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

# Generating backup
write-output "$(Get-Date -format u) - Generating backup." >> .\upgrade\upgrade.log
backup_home
$previous_msi_name = backup_msi

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

# Forces fail
$status = $null

If ($status -eq $null)
{
    write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii
    Get-Service -Name "Wazuh" | Stop-Service

    write-output "$(Get-Date -format u) - Upgrade failed: Restoring former installation." >> .\upgrade\upgrade.log
    restore($previous_msi_name)

    If ($current_process -eq "wazuh-agent")
    {
        .\wazuh-agent.exe install-service >> .\upgrade\upgrade.log
    }
    Else
    {
        sc.exe delete WazuhSvc -ErrorAction SilentlyContinue -Force
        Remove-Item .\wazuh-agent.exe -ErrorAction SilentlyContinue
        Remove-Item .\wazuh-agent.state -ErrorAction SilentlyContinue
        .\ossec-agent.exe install-service >> .\upgrade\upgrade.log
    }
    Start-Service -Name "Wazuh" -ErrorAction SilentlyContinue
}
Else
{
    write-output "0" | out-file ".\upgrade\upgrade_result" -encoding ascii
    write-output "$(Get-Date -format u) - Upgrade finished successfully." >> .\upgrade\upgrade.log
    $new_version = (Get-Content VERSION)
    write-output "$(Get-Date -format u) - New version: $($new_version)" >> .\upgrade\upgrade.log
}

Remove-Item $Env:WAZUH_BACKUP_DIR -recurse -ErrorAction SilentlyContinue
Remove-Item -Path ".\upgrade\*"  -Exclude "*.log", "upgrade_result" -ErrorAction SilentlyContinue
