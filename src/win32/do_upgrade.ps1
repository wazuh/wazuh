# Backup dirs
$Env:WAZUH_BACKUP_DIR         = ".\backup"
$TMP_BACKUP_DIR               = "wazuh_backup_tmp"
# Finding MSI useful constants
$Env:WAZUH_DEF_REG_START_PATH = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\"
$Env:WAZUH_PUBLISHER_VALUE    = "Wazuh, Inc."

# Check if there is an upgrade in progress
$BACKUP_FOLDERS = @()
if (Test-Path $env:temp\$TMP_BACKUP_DIR) { $BACKUP_FOLDERS += "$env:temp\$TMP_BACKUP_DIR" }
if (Test-Path $Env:WAZUH_BACKUP_DIR) { $BACKUP_FOLDERS += "$Env:WAZUH_BACKUP_DIR" }
foreach ($dir in $BACKUP_FOLDERS) {
    $attempts = 5
    while ($attempts -gt 0) {
        Start-Sleep 10
        $attempts--
        if ((Get-ChildItem $dir -recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-1) })) {
            Write-Output "$(Get-Date -Format u) - There is an upgrade in progress. Aborting..." >> .\upgrade\upgrade.log
            exit 1
        }
    }
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

# Check unistall
function is_wazuh_installed
{
    Start-NativePowerShell {

        $retval = $FALSE
        # Searching through the registry keys (Starting from $WAZUH_DEF_REG_START_PATH)
        $path = Get-ChildItem $Env:WAZUH_DEF_REG_START_PATH
        foreach ($subpaths in $path) {
            $subpath = $subpaths | Get-ChildItem
            foreach ($subsubpath in $subpath) {
                if ($subsubpath -match "InstallProperties") {
                    if ($subsubpath.GetValue("Publisher") -match $Env:WAZUH_PUBLISHER_VALUE) {
                        $retval = $TRUE
                    }
                }
            }
        }

        Write-Output $retval
    }
}

# Forces Wazuh-Agent to stop
function stop_wazuh_agent
{
    param (
        $process_name
    )

    write-output "$(Get-Date -format u) - Trying to stop Wazuh service." >> .\upgrade\upgrade.log
    Get-Service -Name "Wazuh" | Stop-Service -ErrorAction SilentlyContinue -Force
    Start-Sleep 2
    $process_id = (Get-Process $process_name -ErrorAction SilentlyContinue).id
    $counter = 5

    while($process_id -ne $null -And $counter -gt 0)
    {
        write-output "$(Get-Date -format u) - Trying to stop Wazuh service again. Remaining attempts: $counter." >> .\upgrade\upgrade.log
        $counter--
        Get-Service -Name "Wazuh" | Stop-Service
        Start-Sleep 2
        $process_id = (Get-Process $process_name -ErrorAction SilentlyContinue).id
    }

    if ($process_id -ne $null) {
        write-output "$(Get-Date -format u) - Killing process." >> .\upgrade\upgrade.log
        taskkill /pid $process_id /f /T
        Start-Sleep 10
    }
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

        write-output "$(Get-Date -format u) - Searching Wazuh-Agent cached MSI through the registry." >> .\upgrade\upgrade.log

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
            write-output "$(Get-Date -format u) - Backing up Wazuh-Agent cached MSI: `"$wazuh_msi_path`"." >> .\upgrade\upgrade.log
            Copy-Item $wazuh_msi_path -Destination $Env:WAZUH_BACKUP_DIR -force
            Write-Output "$msi_filename"
        } else {
            write-output "$(Get-Date -format u) - Wazuh-Agent cached MSI was not found." >> .\upgrade\upgrade.log
        }
    }
}

# Looks for the Wazuh-Agent uninstall command
function get_uninstall_string {

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
		Write-Output $UninstallString
	}
}

# Looks for the Wazuh-Agent uninstall command and executes it, if exists
function uninstall_wazuh {

    $UninstallString = get_uninstall_string

	if ($UninstallString -ne $null) {
		write-output "$(Get-Date -format u) - Performing the Wazuh-Agent uninstall using: `"$UninstallString`"." >> .\upgrade\upgrade.log
		& "$env:windir\System32\cmd.exe"/c $UninstallString

		# registry takes some time to refresh (e.g.: NT 6.3)
		Start-Sleep 5
		$counter = 10
		While((is_wazuh_installed) -And $counter -gt 0) {
			write-output "$(Get-Date -format u) - Waiting for the uninstallation to end." >> .\upgrade\upgrade.log
			$counter--
			Start-Sleep 2
		}
	} else {
		write-output "$(Get-Date -format u) - Wazuh-Agent uninstall command was not found." >> .\upgrade\upgrade.log
	}

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

function restore
{
    param (
        $msi_filename
    )

    kill -processname win32ui -ErrorAction SilentlyContinue -Force
    stop_wazuh_agent("wazuh-agent")

    # Saves ossec.log before remove fail update
    Copy-Item $Env:WAZUH_BACKUP_DIR\ossec.log $Env:WAZUH_BACKUP_DIR\ossec.log.save -force
    Copy-Item ossec.log $Env:WAZUH_BACKUP_DIR\ossec.log -force

    # Uninstall the latest version of the Wazuh-Agent.
    uninstall_wazuh

    # Install the former version of the Wazuh-Agent
    if ($msi_filename -ne $null) {
        write-output "$(Get-Date -format u) - Excecuting former Wazuh-Agent MSI: `"$Env:WAZUH_BACKUP_DIR\$msi_filename`"." >> .\upgrade\upgrade.log
        cmd /c start $Env:WAZUH_BACKUP_DIR\$msi_filename -quiet -norestart -log installer.log

        $counter = 10
        While(-Not (is_wazuh_installed) -And $counter -gt 0) {
            write-output "$(Get-Date -format u) - Waiting for the installation to end." >> .\upgrade\upgrade.log
            $counter--
            Start-Sleep 2
        }
        Remove-Item $Env:WAZUH_BACKUP_DIR\$msi_filename -ErrorAction SilentlyContinue
    }

    # Restore old files
    write-output "$(Get-Date -format u) - Restoring former Wazuh-Agent home files." >> .\upgrade\upgrade.log
    Copy-Item $Env:WAZUH_BACKUP_DIR\* .\ -force

    # Get current version
    $current_version = (Get-Content VERSION)
    write-output "$(Get-Date -format u) - Current version: $($current_version)." >> .\upgrade\upgrade.log
}

# Stop UI and launch the msi installer
function install
{
    kill -processname win32ui -ErrorAction SilentlyContinue -Force
    Remove-Item .\upgrade\upgrade_result -ErrorAction SilentlyContinue
    write-output "$(Get-Date -format u) - Starting upgrade processs." >> .\upgrade\upgrade.log
    cmd /c start /wait (Get-Item ".\wazuh-agent*.msi").Name -quiet -norestart -log installer.log
}


# Get current version
$current_version = (Get-Content VERSION)
write-output "$(Get-Date -format u) - Current version: $($current_version)." >> .\upgrade\upgrade.log

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
stop_wazuh_agent($current_process)

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

$status = $null
If ($status -ne "connected")
{
    Get-Service -Name "Wazuh" | Stop-Service
    write-output "$(Get-Date -format u) - Upgrade failed: Restoring former installation." >> .\upgrade\upgrade.log

    write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii

    .\wazuh-agent.exe uninstall-service >> .\upgrade\upgrade.log
    restore($previous_msi_name)

    If ($current_process -eq "wazuh-agent")
    {
        write-output "$(Get-Date -format u) - Installing Wazuh service." >> .\upgrade\upgrade.log
        .\wazuh-agent.exe install-service >> .\upgrade\upgrade.log
    }
    Else
    {
        write-output "$(Get-Date -format u) - Installing Wazuh service." >> .\upgrade\upgrade.log
        sc.exe delete WazuhSvc -ErrorAction SilentlyContinue -Force
        Remove-Item .\wazuh-agent.exe -ErrorAction SilentlyContinue
        Remove-Item .\wazuh-agent.state -ErrorAction SilentlyContinue
        .\ossec-agent.exe install-service >> .\upgrade\upgrade.log
    }

    write-output "$(Get-Date -format u) - Starting Wazuh-Agent service." >> .\upgrade\upgrade.log
    Start-Service -Name "Wazuh" -ErrorAction SilentlyContinue

}
Else
{
    write-output "0" | out-file ".\upgrade\upgrade_result" -encoding ascii
    write-output "$(Get-Date -format u) - Upgrade finished successfully." >> .\upgrade\upgrade.log
    $new_version = (Get-Content VERSION)
    write-output "$(Get-Date -format u) - New version: $($new_version)." >> .\upgrade\upgrade.log
}

Remove-Item $Env:WAZUH_BACKUP_DIR -recurse -ErrorAction SilentlyContinue
Remove-Item -Path ".\upgrade\*"  -Exclude "*.log", "upgrade_result" -ErrorAction SilentlyContinue
Remove-Item -Path ".\wazuh-agent*.msi" -ErrorAction SilentlyContinue
Remove-Item -Path ".\do_upgrade.ps1" -ErrorAction SilentlyContinue

exit 0
