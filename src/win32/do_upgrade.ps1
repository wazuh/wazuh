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
        # Registry paths to check (in order of preference)
        $registryPaths = @(
            @{Path = "HKLM:\SOFTWARE\WOW6432Node\Wazuh, Inc.\Wazuh Agent"; Key = "WazuhInstallDir"},
            @{Path = "HKLM:\SOFTWARE\WOW6432Node\Wazuh\Wazuh Agent"; Key = "WazuhInstallDir"},
            @{Path = "HKLM:\SOFTWARE\WOW6432Node\ossec"; Key = "Install_Dir"}
        )

        $WazuhInstallDir = $null

        # Try each registry path
        foreach ($reg in $registryPaths) {
            try {
                $WazuhInstallDir = (Get-ItemProperty -Path $reg.Path -ErrorAction SilentlyContinue).($reg.Key)
                if ($null -ne $WazuhInstallDir) {
                    Write-output "$(Get-Date -format u) - Found Wazuh installation at: $($reg.Path)\$($reg.Key) = $WazuhInstallDir" >> .\upgrade\upgrade.log
                    break
                }
            }
            catch {
                continue
            }
        }

        # Fallback to current directory if not found in registry
        if ($null -eq $WazuhInstallDir) {
            Write-output "$(Get-Date -format u) - Couldn't find Wazuh in registry. Using current directory" >> .\upgrade\upgrade.log
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
    $actual_version = get-version
    $counter = 5
    while($actual_version -eq $current_version -And $counter -gt 0) {
        write-output "$(Get-Date -format u) - Waiting for the Wazuh-Agent installation to end." >> .\upgrade\upgrade.log
        $counter--
        Start-Sleep 2
        $actual_version = get-version
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
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/a", "`"$msiPath`"", "/qn", "TARGETDIR=$env:TEMP", "/lv*", "`".\upgrade\msi_output.log`"" -Wait

        $msi_version = Get-MSIProductVersion ".\upgrade\msi_output.log"
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
        # Match "ProductVersion = x.y.z" and take the first hit. Matching directly with
        # Select-String avoids running -match against a collection of lines, which does not
        # populate $Matches and would leave a stale or empty version.
        $match = Get-Content $logFilePath | Select-String -Pattern "ProductVersion\s*=\s*([0-9\.]+)" | Select-Object -First 1

        # Check if the version format is valid
        if (-not $match) {
            write-output "$(Get-Date -format u) - Invalid ProductVersion format in the MSI log: $logFilePath" >> .\upgrade\upgrade.log
            return $null
        }

        # Return the version with the 'v' prefix
        $product_version = "v$($match.Matches[0].Groups[1].Value)"
        return $product_version

    } catch {
        # Log any errors that occur
        write-output "$(Get-Date -format u) - Error extracting ProductVersion from MSI log: $($logFilePath). Error: $($_.Exception.Message)" >> .\upgrade\upgrade.log
        return $null
    }
}



# Stop UI and launch the MSI installer
function install {
    param (
        [string]$installDir
    )

    # Try to stop win32ui
    try {
        Write-Output "$(Get-Date -format u) - Stopping win32ui process." >> .\upgrade\upgrade.log
        Stop-Process -Name "win32ui" -Force -ErrorAction Stop
    } catch {
        Write-Output "$(Get-Date -format u) - Tried to stop process win32ui: $($_.Exception.Message)" >> .\upgrade\upgrade.log
    }

    # Try to stop Wazuh service
    try {
        Write-Output "$(Get-Date -format u) - Stopping Wazuh service." >> .\upgrade\upgrade.log
        Stop-Service -Name "Wazuh" -Force -ErrorAction Stop
    } catch {
        Write-Output "$(Get-Date -format u) - Tried to stop Wazuh service: $($_.Exception.Message)" >> .\upgrade\upgrade.log
    }

    # Wait for Wazuh service to fully stop
    Start-Sleep -Seconds 5
    Remove-Item .\upgrade\upgrade_result -ErrorAction SilentlyContinue
    Write-Output "$(Get-Date -format u) - Starting upgrade process." >> .\upgrade\upgrade.log

    try {
        $msiPath = (Get-Item ".\wazuh-agent*.msi").Name

        if ($msi_new_version -ne $null -and $msi_new_version -eq $current_version) {
            Write-Output "$(Get-Date -format u) - Reinstalling the same version." >> .\upgrade\upgrade.log
        }

        # Build msiexec arguments with explicit APPLICATIONFOLDER
        $msiArgs = @(
            "/i",
            $msiPath,
            "APPLICATIONFOLDER=`"$installDir`"",
            "WIXUI_INSTALLDIR=APPLICATIONFOLDER",
            "REBOOT=ReallySuppress",
            "/qn",
            "/l*v",
            "installer.log"
        )

        write-output "$(Get-Date -format u) - Installing MSI to: $installDir (msiexec.exe $($msiArgs -join ' '))" >> .\upgrade\upgrade.log

        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -NoNewWindow -PassThru
        write-output "$(Get-Date -format u) - msiexec finished with exit code: $($process.ExitCode)." >> .\upgrade\upgrade.log

        return $process.ExitCode

    } catch {
        Write-Output "$(Get-Date -format u) - Installation failed: $($_.Exception.Message)" >> .\upgrade\upgrade.log
        return -1
    }
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
$current_version = get-version
write-output "$(Get-Date -format u) - Current version: $($current_version)." >> .\upgrade\upgrade.log

# Get new msi version
$msi_new_version = get_msi_version
if ($msi_new_version -ne $null) {
  write-output "$(Get-Date -format u) - MSI new version: $($msi_new_version)." >> .\upgrade\upgrade.log
} else {
  write-output "$(Get-Date -format u) - Could not find version in MSI file." >> .\upgrade\upgrade.log
}


# Check version compatibility: direct upgrade to 5.x requires agent >= 4.14
if ($msi_new_version -ne $null) {
    try {
        $target_ver = [Version]($msi_new_version -replace '^v', '')
        $current_ver = [Version]($current_version -replace '^v', '')
        if ($target_ver -ge [Version]"5.0.0" -and $current_ver -lt [Version]"4.14.0") {
            write-output "$(Get-Date -format u) - Upgrade failed: direct upgrade to v5.0.0 is not supported from version $($current_version). Please upgrade to v4.14.x first." >> .\upgrade\upgrade.log
            write-output "1" | out-file ".\upgrade\upgrade_result" -encoding ascii
            remove_upgrade_files
            Restart-Service -Name "Wazuh" -Force -ErrorAction SilentlyContinue
            exit 1
        }
    } catch {
        write-output "$(Get-Date -format u) - Could not compare versions for compatibility check: $($_.Exception.Message)" >> .\upgrade\upgrade.log
        write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii
        remove_upgrade_files
        Restart-Service -Name "Wazuh" -Force -ErrorAction SilentlyContinue
        exit 1
    }
}

# Read the first <tag> nested in <block> from the agent configuration
function get_conf_value($block, $tag) {
    $conf_path = Join-Path $wazuhDir "ossec.conf"
    if (-Not (Test-Path $conf_path)) {
        return $null
    }
    # Strip CR and LF independently: the shipped template is LF-only, and .NET's `.`
    # does not cross a newline, so a CRLF-only strip leaves the block unmatchable.
    $conf = (Get-Content $conf_path -Raw) -replace "`r", "" -replace "`n", ""
    $block_match = [regex]::Match($conf, "<$block>(.*)</$block>")
    if (-Not $block_match.Success) {
        return $null
    }
    $tag_match = [regex]::Match($block_match.Groups[1].Value, "<$tag>([^<]*)</$tag>")
    if (-Not $tag_match.Success) {
        return $null
    }
    return $tag_match.Groups[1].Value.Trim()
}

# Check that the manager accepts connections on the HTTPS control port
function probe_manager($server, $port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($server, [int]$port, $null, $null)
        if (-Not $async.AsyncWaitHandle.WaitOne(5000, $false)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

# The 5x agent requires the manager address inside the <agent> block, falling back to the <client> block when upgrading from 4x versions.
$manager_address = get_conf_value "agent" "address"
if ([string]::IsNullOrEmpty($manager_address)) {
    $manager_address = get_conf_value "client" "address"
}

# The 5x agent requires the manager port inside the <agent> block, falling back to 1517 when upgrading from 4x versions.
$manager_port = get_conf_value "agent" "port"
if ([string]::IsNullOrEmpty($manager_port)) {
    $manager_port = "1517"
}

if ([string]::IsNullOrEmpty($manager_address)) {
    write-output "$(Get-Date -format u) - Upgrade failed: no manager address found in the configuration." >> .\upgrade\upgrade.log
    write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii
    remove_upgrade_files
    Restart-Service -Name "Wazuh" -Force -ErrorAction SilentlyContinue
    exit 1
}

write-output "$(Get-Date -format u) - Checking connectivity to $($manager_address):$($manager_port)." >> .\upgrade\upgrade.log

if (-Not (probe_manager $manager_address $manager_port)) {
    write-output "$(Get-Date -format u) - Upgrade failed: the manager is not reachable at $($manager_address):$($manager_port), interrupting upgrade." >> .\upgrade\upgrade.log
    write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii
    remove_upgrade_files
    Restart-Service -Name "Wazuh" -Force -ErrorAction SilentlyContinue
    exit 1
}

write-output "$(Get-Date -format u) - Manager reachable at $($manager_address):$($manager_port)." >> .\upgrade\upgrade.log

# Ensure no other instance of msiexec is running by stopping them
try {
    $proc = Get-Process -Name "msiexec" -ErrorAction Stop
    Stop-Process -InputObject $proc -Force -ErrorAction Stop
    Write-Output "$(Get-Date -Format u) - Killed msiexec process(es)." >> .\upgrade\upgrade.log
} catch {
    Write-Output "$(Get-Date -Format u) - Tried to stop msiexec process: $($_.Exception.Message)" >> .\upgrade\upgrade.log
}

# Install with explicit INSTALLDIR
$msi_exit_code = install -installDir $wazuhDir
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

# Verify the committed on-disk state before reporting success, instead of trusting
# the staged files alone. The upgrade is successful only if msiexec committed cleanly
# (exit code 0; a reboot-required result is a failure because a restart is never
# allowed), the version written to disk matches the MSI, and the agent reconnects.
$new_version = get-version
if ($msi_new_version -eq $null) {
    write-output "$(Get-Date -format u) - Skipping on-disk version check: the MSI version could not be determined." >> .\upgrade\upgrade.log
    $version_ok = $true
} else {
    $version_ok = ("v$new_version" -eq $msi_new_version)
}

if ($msi_exit_code -ne 0 -Or (-Not $version_ok) -Or ($status -ne "connected")) {
    write-output "$(Get-Date -format u) - Upgrade failed (msiexec exit code: $($msi_exit_code), on-disk version: $($new_version), status: $($status))." >> .\upgrade\upgrade.log
    write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii
}
else {
    write-output "0" | out-file ".\upgrade\upgrade_result" -encoding ascii
    write-output "$(Get-Date -format u) - Upgrade finished successfully. New version: $($new_version)." >> .\upgrade\upgrade.log
}

remove_upgrade_files

exit 0
