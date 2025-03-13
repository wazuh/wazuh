# Check if there is an upgrade in progress
if (Test-Path ".\upgrade\upgrade_in_progress") {
    write-output "$(Get-Date -format u) - There is an upgrade in progress. Aborting..." >> .\upgrade\upgrade.log
    exit 1
}

write-output "0" | out-file ".\upgrade\upgrade_in_progress" -encoding ascii

# Delete previous upgrade.log
Remove-Item -Path ".\upgrade\upgrade.log" -ErrorAction SilentlyContinue

# Select powershell
if (Test-Path "$env:windir\sysnative") {
    write-output "$(Get-Date -format u) - Sysnative Powershell will be used to access the registry." >> .\upgrade\upgrade.log
    Set-Alias Start-NativePowerShell "$env:windir\sysnative\WindowsPowerShell\v1.0\powershell.exe"
} else {
    Set-Alias Start-NativePowerShell "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
}


function get-version {
    # possible version file paths
    $JsonFile = "VERSION.json"
    $TextFile = "VERSION"
    $version = $null

    # first check JSON version file exists
    if (Test-Path $JsonFile) {
        $VERSION_JSON = Get-Content $JsonFile -Raw

        if ($VERSION_JSON -match "['""]version['""]\s*:\s*['""]([^'""]+)['""]") {
            $version = $matches[1]
            Write-Output "$(Get-Date -format u) - Extracted version from $JsonFile : $version." >> .\upgrade\upgrade.log
        } else {
            Write-Output "$(Get-Date -format u) - Failed to extract version from JSON file $JsonFile." >> .\upgrade\upgrade.log
            exit 1
        }
    }
    # fallback to the plain text VERSION file
    elseif (Test-Path $TextFile) {
        $version = Get-Content $TextFile -Raw
        $version = $version.Trim() -replace "^v", ""
        Write-Output "$(Get-Date -format u) - Extracted version from $TextFile : $version." >> .\upgrade\upgrade.log
    } else {
        Write-Output "$(Get-Date -format u) - Error: No version file found (expected $JsonFile or $TextFile)." >> .\upgrade\upgrade.log
        exit 1
    }

    return $version
}


function remove_upgrade_files {
    Remove-Item -Path ".\upgrade\*"  -Exclude "*.log", "upgrade_result" -ErrorAction SilentlyContinue
    Remove-Item -Path ".\wazuh-agent*.msi" -ErrorAction SilentlyContinue
    Remove-Item -Path ".\do_upgrade.ps1" -ErrorAction SilentlyContinue
}


function get_wazuh_installation_directory {
    Start-NativePowerShell {
        $path1 = "HKLM:\SOFTWARE\WOW6432Node\Wazuh, Inc.\Wazuh Agent"
        $key1 = "WazuhInstallDir"

        $path2 = "HKLM:\SOFTWARE\WOW6432Node\ossec"
        $key2 = "Install_Dir"

        $WazuhInstallDir = $null

        try {
            $WazuhInstallDir = (Get-ItemProperty -Path $path1 -ErrorAction SilentlyContinue).$key1
        }
        catch {
            $WazuhInstallDir = $null
        }

        if ($null -eq $WazuhInstallDir) {
            try {
                $WazuhInstallDir = (Get-ItemProperty -Path $path2 -ErrorAction SilentlyContinue).$key2
            }
            catch {
                $WazuhInstallDir = $null
            }
        }

        if ($null -eq $WazuhInstallDir) {
            Write-output "$(Get-Date -format u) - Couldn't find Wazuh in the registry. Upgrade will assume current path is correct" >> .\upgrade\upgrade.log
            $WazuhInstallDir = (Get-Location).Path.TrimEnd('\')
        }

        return $WazuhInstallDir
    }
}

# Check process status
function check-process {
    $process_id = (Get-Process wazuh-agent).id
    $counter = 10
    while($process_id -eq $null -And $counter -gt 0) {
        $counter--
        Start-Service -Name "Wazuh"
        Start-Sleep 2
        $process_id = (Get-Process wazuh-agent).id
    }
    write-output "$(Get-Date -format u) - Process ID: $($process_id)." >> .\upgrade\upgrade.log
}

# Check new version and restart the Wazuh service
function check-installation {
    $actual_version = get_version
    $counter = 5
    while($actual_version -eq $current_version -And $counter -gt 0) {
        write-output "$(Get-Date -format u) - Waiting for the Wazuh-Agent installation to end." >> .\upgrade\upgrade.log
        $counter--
        Start-Sleep 2
        $actual_version = get_version
    }
    write-output "$(Get-Date -format u) - Starting Wazuh-Agent service." >> .\upgrade\upgrade.log
    Start-Service -Name "Wazuh"
}

# Function to extract the version from the MSI using msiexec
function get_msi_version {
    $msiPath = (Get-Item ".\wazuh-agent*.msi").FullName
    write-output "$(Get-Date -format u) - Extracting the version from MSI file." >> .\upgrade\upgrade.log
    try {
        # Extracting the version using msiexec and waiting for it to complete
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/a", "`"$msiPath`"", "/qn", "TARGETDIR=$env:TEMP", "/lv*", "`".\upgrade\msi_output.txt`"" -Wait

        $msi_version = Get-MSIProductVersion ".\upgrade\msi_output.txt"
        return $msi_version

    } catch {
        # Log any errors that occur during the process
        write-output "$(Get-Date -format u) - Couldn't extract MSI version. Error: $($_.Exception.Message)" >> .\upgrade\upgrade.log
        return $null
    }
}

function Get-MSIProductVersion {
    param (
        [string]$logFilePath
    )

    # Check if the log file exists
    if (-not (Test-Path $logFilePath)) {
        write-output "$(Get-Date -format u) - MSI log file not generated: $logFilePath" >> .\upgrade\upgrade.log
        return $null
    }

    try {
        # Get the line that contains "ProductVersion"
        $msi_version_info = Get-Content $logFilePath | Select-String "ProductVersion" | ForEach-Object { $_.Line }

        # Check if the version format is valid
        if (-not ($msi_version_info -match "ProductVersion\s*=\s*([0-9\.]+)")) {
            write-output "$(Get-Date -format u) - Invalid ProductVersion format in the MSI log: $logFilePath" >> .\upgrade\upgrade.log
            return $null
        }

        # Return the version with the 'v' prefix
        $product_version = "v$($matches[1])"
        return $product_version

    } catch {
        # Log any errors that occur
        write-output "$(Get-Date -format u) - Error extracting ProductVersion from MSI log: $($logFilePath). Error: $($_.Exception.Message)" >> .\upgrade\upgrade.log
        return $null
    }
}



# Stop UI and launch the MSI installer
function install {
    kill -processname win32ui -ErrorAction SilentlyContinue -Force
    Stop-Service -Name "Wazuh"
    Remove-Item .\upgrade\upgrade_result -ErrorAction SilentlyContinue
    write-output "$(Get-Date -format u) - Starting upgrade process." >> .\upgrade\upgrade.log

    try {
        $msiPath = (Get-Item ".\wazuh-agent*.msi").Name

        if ($msi_new_version -ne $null -and $msi_new_version -eq $current_version) {
            write-output "$(Get-Date -format u) - Reinstalling the same version." >> .\upgrade\upgrade.log
        }

        Start-Process -FilePath "msiexec.exe" -ArgumentList @("/i", $msiPath, '-quiet', '-norestart', '-log', 'installer.log') -Wait -NoNewWindow

    } catch {
        write-output "$(Get-Date -format u) - Installation failed: $($_.Exception.Message)" >> .\upgrade\upgrade.log
        return $false
    }

    return $true
}

# Check that the Wazuh installation runs on the expected path
$wazuhDir = get_wazuh_installation_directory
$normalizedWazuhDir = $wazuhDir.TrimEnd('\')
$currentDir = (Get-Location).Path.TrimEnd('\')

if ($normalizedWazuhDir -ne $currentDir) {
    Write-Output "$(Get-Date -format u) - Current working directory is not the Wazuh installation directory. Aborting." >> .\upgrade\upgrade.log
    Write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii
    remove_upgrade_files
    exit 1
}

# Get current version
$current_version = get_version
write-output "$(Get-Date -format u) - Current version: $($current_version)." >> .\upgrade\upgrade.log

# Get new msi version
$msi_new_version = get_msi_version
if ($msi_new_version -ne $null) {
  write-output "$(Get-Date -format u) - MSI new version: $($msi_new_version)." >> .\upgrade\upgrade.log
} else {
  write-output "$(Get-Date -format u) - Could not find version in MSI file." >> .\upgrade\upgrade.log
}


# Ensure no other instance of msiexec is running by stopping them
Get-Process msiexec | Stop-Process -ErrorAction SilentlyContinue -Force

# Install
install
check-installation

write-output "$(Get-Date -format u) - Installation finished." >> .\upgrade\upgrade.log

check-process

# Wait for agent state to be cleaned
Start-Sleep 10

# Check status file
function Get-AgentStatus {
    Select-String -Path '.\wazuh-agent.state' -Pattern "^status='(.+)'" | %{$_.Matches[0].Groups[1].value}
}

$status = Get-AgentStatus
$counter = 30
while($status -ne "connected"  -And $counter -gt 0) {
    $counter--
    Start-Sleep 2
    $status = Get-AgentStatus
}
Write-Output "$(Get-Date -Format u) - Reading status file: status='$status'." >> .\upgrade\upgrade.log

if ($status -ne "connected") {
    write-output "$(Get-Date -format u) - Upgrade failed." >> .\upgrade\upgrade.log
    write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii
}
else {
    write-output "0" | out-file ".\upgrade\upgrade_result" -encoding ascii
    write-output "$(Get-Date -format u) - Upgrade finished successfully." >> .\upgrade\upgrade.log
    $new_version = get_version
    write-output "$(Get-Date -format u) - New version: $($new_version)." >> .\upgrade\upgrade.log
}

remove_upgrade_files

exit 0
