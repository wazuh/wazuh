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
            return $null
        }
    }
    # fallback to the plain text VERSION file
    elseif (Test-Path $TextFile) {
        $version = Get-Content $TextFile -Raw
        $version = $version.Trim() -replace "^v", ""
        Write-Output "$(Get-Date -format u) - Extracted version from $TextFile : $version." >> .\upgrade\upgrade.log
    } else {
        Write-Output "$(Get-Date -format u) - Error: No version file found (expected $JsonFile or $TextFile)." >> .\upgrade\upgrade.log
        return $null
    }

    return $version
}


function remove_upgrade_files {
    Remove-Item -Path ".\upgrade\*"  -Exclude "*.log", "upgrade_result" -ErrorAction SilentlyContinue
    Remove-Item -Path ".\wazuh-agent*.msi" -ErrorAction SilentlyContinue
    Remove-Item -Path ".\do_upgrade.ps1" -ErrorAction SilentlyContinue
}


# Write the upgrade result, remove upgrade files and restart the service
function abort_upgrade($code) {
    write-output "$code" | out-file ".\upgrade\upgrade_result" -encoding ascii
    remove_upgrade_files
    Restart-Service -Name "Wazuh" -Force -ErrorAction SilentlyContinue
    exit 1
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
    while(($null -eq $actual_version -Or $actual_version -eq $current_version) -And $counter -gt 0) {
        write-output "$(Get-Date -format u) - Waiting for the Wazuh-Agent installation to end." >> .\upgrade\upgrade.log
        $counter--
        Start-Sleep 2
        $actual_version = get-version
    }
    if ($null -eq $actual_version) {
        write-output "$(Get-Date -format u) - Could not read the installed version after the installation." >> .\upgrade\upgrade.log
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
    abort_upgrade "2"
}

# Get current version
$current_version = get-version
if ($null -eq $current_version) {
    write-output "$(Get-Date -format u) - Upgrade failed: could not read the current agent version." >> .\upgrade\upgrade.log
    abort_upgrade "2"
}
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
            abort_upgrade "1"
        }
    } catch {
        write-output "$(Get-Date -format u) - Could not compare versions for compatibility check: $($_.Exception.Message)" >> .\upgrade\upgrade.log
        abort_upgrade "2"
    }
}

# Read <block><sub><tag> from the agent configuration, taking the last match.
function get_conf_value($block, $sub, $tag) {
    $conf_path = Join-Path $wazuhDir "ossec.conf"
    if (-Not (Test-Path $conf_path)) {
        return $null
    }
    # Strip CR and LF separately: the shipped template is LF-only, and `.` never matches a newline.
    $conf = (Get-Content $conf_path -Raw) -replace "`r", "" -replace "`n", ""
    $block_match = [regex]::Match($conf, "<$block>(.*)</$block>")
    if (-Not $block_match.Success) {
        return $null
    }
    $sub_match = [regex]::Match($block_match.Groups[1].Value, "<$sub>(.*)</$sub>")
    if (-Not $sub_match.Success) {
        return $null
    }
    $tag_matches = [regex]::Matches($sub_match.Groups[1].Value, "<$tag>([^<]*)</$tag>")
    if ($tag_matches.Count -eq 0) {
        # A self-closing <tag/> is present, not absent: OS_XML parses it as exactly
        # equivalent to <tag></tag> (see test_simple_nodes3, src/unit_tests/os_xml),
        # so report it as present-but-empty ("") rather than absent ($null). Callers
        # that only test IsNullOrEmpty are unaffected; the one caller that needs the
        # distinction is <endpoint>'s opt-out (#38492).
        if ([regex]::IsMatch($sub_match.Groups[1].Value, "<$tag\s*/>")) {
            return ""
        }
        return $null
    }
    return $tag_matches[$tag_matches.Count - 1].Groups[1].Value.Trim()
}

# Accept any certificate: the manager's is self-signed. Compiled, because .NET calls this
# on a worker thread where a PowerShell scriptblock cannot run.
if (-not ("WazuhProbeTrust" -as [type])) {
    Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class WazuhProbeTrust {
    public static RemoteCertificateValidationCallback Always =
        delegate (object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; };
}
"@
}

# Check the manager is up: GET /<endpoint>/ is remoted's health endpoint and answers 200 -- the
# request must include the manager's reverse-proxy prefix (#38492/#38491) or it 404s.
# Never pin the TLS version here: the listener is TLS 1.3-only, so Tls12 fails the handshake.
function probe_server($server, $port, $endpoint) {
    $saved_callback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [WazuhProbeTrust]::Always
        $path = if ([string]::IsNullOrEmpty($endpoint)) { "/" } else { "/$endpoint/" }

        # $server holds an IPv6 literal unbracketed, the way <endpoint> stores it. A URL
        # needs it bracketed again or Invoke-WebRequest rejects the value as malformed
        # and the upgrade aborts with "manager is not reachable".
        $host_part = $server
        if ($host_part.Contains(":") -And -Not $host_part.StartsWith("[")) {
            $host_part = "[$host_part]"
        }

        $response = Invoke-WebRequest -Uri "https://$($host_part):$($port)$($path)" -UseBasicParsing -TimeoutSec 5
        return ($response.StatusCode -eq 200)
    } catch {
        return $false
    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $saved_callback
    }
}

# Defaults for the components an <endpoint> value leaves out, matching the agent's own
# (DEFAULT_HTTPS_REMOTE_PORT and the manager's default global_prefix, #38491).
$MEP_DEFAULT_PORT = "1517"
$MEP_DEFAULT_ENDPOINT = "wazuh-manager"

# Split a combined <endpoint> value (#38624) into $MEP_HOST / $MEP_PORT / $MEP_ENDPOINT:
#
#   [https://] host [:port] [/[prefix]]
#
# Only the host is mandatory. "No '/' at all" means the default prefix; "a trailing '/'
# with nothing after it" is the operator's deliberate opt-out (#38614) and yields "".
#
# Same logic as parse_manager_endpoint() in src/init/pkg_installer.sh; duplicated because
# this script ships inside the WPK and runs standalone, with nothing to import.
function ParseManagerEndpoint($raw) {
    $script:MEP_HOST = ""
    $script:MEP_PORT = $MEP_DEFAULT_PORT
    $script:MEP_ENDPOINT = $MEP_DEFAULT_ENDPOINT

    if ([string]::IsNullOrEmpty($raw)) {
        return $false
    }

    $rest = $raw

    # Optional scheme, only where no '/' precedes the "://" so a path containing it
    # cannot be mistaken for one.
    $p = $rest.IndexOf("://")
    if ($p -ge 0) {
        $scheme = $rest.Substring(0, $p)
        if (-Not $scheme.Contains("/")) {
            if ($scheme.ToLower() -ne "https") {
                return $false
            }
            $rest = $rest.Substring($p + 3)
        }
    }

    # Authority up to the first '/', prefix after it. Whether that '/' was there at all
    # is what separates "default prefix" from "opt-out".
    $p = $rest.IndexOf("/")
    if ($p -ge 0) {
        $authority = $rest.Substring(0, $p)
        $path = $rest.Substring($p + 1)
        $path_given = $true
    } else {
        $authority = $rest
        $path = ""
        $path_given = $false
    }

    $port_given = ""
    if ($authority.StartsWith("[")) {
        $p = $authority.IndexOf("]")
        if ($p -lt 0) { return $false }
        $script:MEP_HOST = $authority.Substring(1, $p - 1)
        $after = $authority.Substring($p + 1)
        if ($after -ne "") {
            if ($after.StartsWith(":")) { $port_given = $after.Substring(1) } else { return $false }
        }
    } else {
        $colons = ($authority.ToCharArray() | Where-Object { $_ -eq ':' }).Count
        if ($colons -gt 1) {
            return $false
        } elseif ($colons -eq 1) {
            $p = $authority.IndexOf(":")
            $script:MEP_HOST = $authority.Substring(0, $p)
            $port_given = $authority.Substring($p + 1)
        } else {
            $script:MEP_HOST = $authority
        }
    }

    if ([string]::IsNullOrEmpty($script:MEP_HOST)) { return $false }

    if ($port_given -ne "") {
        if ($port_given -notmatch '^[0-9]+$') { return $false }
        if ([int64]$port_given -lt 1 -or [int64]$port_given -gt 65535) { return $false }
        $script:MEP_PORT = $port_given
    } elseif ($authority.EndsWith(":")) {
        return $false
    }

    if ($path_given) {
        $script:MEP_ENDPOINT = $path.Trim('/')
    }

    return $true
}

# A WPK upgrade never rewrites ossec.conf, so this script meets two config shapes and has
# to read both (#38624):
#
#   current  <agent><manager><endpoint>  carrying host[:port][/prefix] in one value
#   upgraded the deprecated <agent><manager><address>/<port>, or a 4.x
#            <client><server><address> -- neither has an endpoint concept
#
# <endpoint> always carries the whole target, so no disambiguation is needed: its presence
# alone decides, exactly as Read_Agent_Manager() does. get_conf_value returns $null for
# "tag absent" and "" for "tag present but empty", so test against $null specifically.
$server_address = $null
$server_port = $null
$server_endpoint = $null
$combined_endpoint = get_conf_value "agent" "manager" "endpoint"

if ($null -ne $combined_endpoint) {
    # Split the one value the same way the agent's parser does. An empty <endpoint> fails
    # here just as it does there, leaving $server_address unset for the check below.
    if (ParseManagerEndpoint $combined_endpoint) {
        $server_address = $MEP_HOST
        $server_port = $MEP_PORT
        $server_endpoint = $MEP_ENDPOINT
    }
} else {
    # Compose the same target the agent composes internally from the deprecated tags:
    # the address, <port> or its 1517 default, and the default prefix.
    $server_address = get_conf_value "agent" "manager" "address"
    $server_port = get_conf_value "agent" "manager" "port"

    if ([string]::IsNullOrEmpty($server_address)) {
        # 4.x shape. Its <port> is not read by the agent either, so leave it defaulted.
        $server_address = get_conf_value "client" "server" "address"
        $server_port = $null
    }

    $server_endpoint = "wazuh-manager"
}

if ([string]::IsNullOrEmpty($server_port)) {
    $server_port = "1517"
}
if ($null -eq $server_endpoint) {
    $server_endpoint = ""
}
$server_endpoint = $server_endpoint.Trim('/')

if ([string]::IsNullOrEmpty($server_address)) {
    write-output "$(Get-Date -format u) - Upgrade failed: no manager address found in the configuration." >> .\upgrade\upgrade.log
    abort_upgrade "2"
}

write-output "$(Get-Date -format u) - Checking connectivity to $($server_address):$($server_port) (endpoint: '$($server_endpoint)')." >> .\upgrade\upgrade.log

if ($env:WAZUH_UPGRADE_TEST_SKIP_MANAGER_CHECK -eq "1") {
    write-output "$(Get-Date -format u) - Manager connectivity check skipped (test mode)." >> .\upgrade\upgrade.log
} elseif (-Not (probe_server $server_address $server_port $server_endpoint)) {
    write-output "$(Get-Date -format u) - Upgrade failed: the manager is not reachable at $($server_address):$($server_port) (endpoint: '$($server_endpoint)'), interrupting upgrade." >> .\upgrade\upgrade.log
    abort_upgrade "2"
} else {
    write-output "$(Get-Date -format u) - Manager reachable at $($server_address):$($server_port) (endpoint: '$($server_endpoint)')." >> .\upgrade\upgrade.log
}

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
