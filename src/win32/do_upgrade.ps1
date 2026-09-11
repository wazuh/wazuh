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



# True if $path is a reparse point (symlink or junction), regardless of whether its
# target exists. Uses the raw .NET FileAttributes flag rather than Get-Item's
# LinkType convenience property: LinkType requires PowerShell 5.0+, and this script
# otherwise targets much older hosts (see Start-NativePowerShell's "Windows
# PowerShell v1.0" path above) -- on an older PowerShell, LinkType is simply absent
# ($null), which would leave every reparse-point check below silently inert instead
# of failing loudly. FileAttributes.ReparsePoint has existed since .NET 1.1.
function Test-IsReparsePoint($path) {
    try {
        $attrs = [System.IO.File]::GetAttributes($path)
        return (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    } catch {
        return $false
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

# Read <block><sub><tag> from the agent configuration, taking the last match.
# Strips commented-out lines before get_conf_value extracts anything, so a
# tag an operator comments out (e.g. to fall back to the default) reads as absent here too,
# matching OS_XML's own comment handling and pkg_installer.sh's strip_xml_comments() on the
# Linux/macOS side. Defined ahead of the CA-adoption block below, which needs
# get_conf_value to check for an operator-pinned <certificate_authorities>.
function strip_xml_comments($conf_path) {
    $in_comment = $false
    $result = New-Object System.Collections.Generic.List[string]
    foreach ($line in (Get-Content $conf_path)) {
        if ($in_comment) {
            if ($line -match '-->') { $in_comment = $false }
            continue
        }
        # A self-contained one-line comment ("<!-- ... -->", both on this line) must be
        # dropped here too, not just one that opens on this line and closes later --
        # get_conf_value does unanchored regex matching on the result, so
        # a commented-out example left in would otherwise be read as live.
        if ($line -match '<!--' -and $line -match '-->') {
            continue
        }
        if ($line -match '<!--' -and $line -notmatch '-->') {
            $in_comment = $true
            continue
        }
        $result.Add($line)
    }
    return ($result -join "`n")
}

function get_conf_value($block, $sub, $tag) {
    $conf_path = Join-Path $wazuhDir "ossec.conf"
    if (-Not (Test-Path $conf_path)) {
        return $null
    }
    # The shipped template is LF-only, and `.` never matches a newline.
    $conf = (strip_xml_comments $conf_path) -replace "`n", ""
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

# Default drop-in location for the manager's CA (mirrored on Linux/macOS in
# pkg_installer.sh): an operator can place it here ahead of an upgrade without having
# to hand-edit ossec.conf, and it also doubles as the on-disk anchor path for a CA
# delivered by the manager (below). Resolves to <install_dir>\certs\root-ca.pem, same
# as AGENT_ANCHOR_CA (src/shared/include/defs.h) on Windows.
$default_ca_file = Join-Path $wazuhDir "certs\root-ca.pem"

# Detect and validate a manager-delivered CA. The manager streams its root CA
# into the incoming-transfer directory under this reserved filename over the com
# channel, before issuing the upgrade command -- never look in the upgrade
# directory (".\upgrade"), since it is cleared before this script runs, same as
# UPGRADE_DIR on the Linux/macOS side. Runs after the version-compatibility check
# above (an unsupported version jump must abort before anything is installed, not
# after), but still ahead of the manager connectivity check and the <ssl> gate below.
#
# Installing the file is the entire cutover here -- ossec.conf is never edited. Mirrors
# pkg_installer.sh's INCOMING_CA_FILE handling; see that file for the
# full rationale on why wiring this into <ssl><certificate_authorities> is a separate,
# explicitly recorded decision rather than done implicitly here.
$incoming_ca_file = Join-Path $wazuhDir "incoming\root-ca.pem"

# Set once the delivered CA passes validation; it is installed further down, past
# the last gate that can abort this upgrade.
$ca_validated = $false

# incoming\ is written by com's own transfer, but is not exclusively Wazuh-controlled --
# reject a reparse point (symlink/junction) outright rather than read through it, same
# reasoning as pkg_installer.sh's symlink rejection for the equivalent Linux/macOS path.
# Get-Item -Force is the sole existence check here, deliberately not Test-Path
# -PathType Leaf: Test-Path resolves through a reparse point to confirm the
# TARGET exists, so it returns $false for a dangling symlink/junction, and a
# dangling one would then never reach the LinkType branch below to be removed
# -- contradicting this function's own "always removes the incoming file"
# guarantee. Get-Item surfaces the reparse point's own metadata regardless of
# whether its target exists, so it catches a dangling link too.
$incoming_item = Get-Item -Force -ErrorAction SilentlyContinue $incoming_ca_file
if (-Not $incoming_item) {
    Write-Output "$(Get-Date -format u) - No CA delivered by the manager at $($incoming_ca_file) this run." >> .\upgrade\upgrade.log
} elseif (Test-IsReparsePoint $incoming_ca_file) {
    Write-Output "$(Get-Date -format u) - A CA arrived at $($incoming_ca_file) as a symlink/junction; refusing to follow it, discarding it and continuing the upgrade unverified." >> .\upgrade\upgrade.log
    Remove-Item -Force -ErrorAction SilentlyContinue $incoming_ca_file
} else {
    Write-Output "$(Get-Date -format u) - Found a CA delivered by the manager at $($incoming_ca_file), validating it." >> .\upgrade\upgrade.log

    $ca_reject_reason = $null
    $ca_cert = $null
    $ca_pem = $null
    $ca_snapshot = Join-Path $wazuhDir "upgrade\.root-ca.pem.incoming-snapshot.tmp"

    # incoming\ is not exclusively Wazuh-controlled: a file that validated as a
    # legitimate CA a moment ago could be swapped for a reparse point or a hard
    # link to an attacker-chosen certificate before a later step re-reads the
    # same path -- the LinkType check above and this point are separate
    # filesystem accesses, wide enough for that swap. Re-check LinkType and the
    # hard-link count again, immediately adjacent to the only read of this
    # path, then snapshot into .\upgrade\ (not attacker-writable, unlike
    # incoming\) and validate/install from that snapshot alone from here on --
    # mirrors pkg_installer.sh's equivalent pattern on Linux/macOS. NTFS hard
    # links aren't reparse points, so LinkType alone doesn't catch one; fsutil
    # hardlink list does (a file with only its own name reports exactly 1).
    $hardlink_count = 0
    try {
        $hardlink_count = (fsutil hardlink list $incoming_ca_file 2>$null | Measure-Object).Count
    } catch {
        $hardlink_count = 0
    }

    if ((Test-IsReparsePoint $incoming_ca_file) -or $hardlink_count -gt 1) {
        $ca_reject_reason = "is a symlink/junction or has more than one hard link"
    } else {
        try {
            Copy-Item -Path $incoming_ca_file -Destination $ca_snapshot -Force -ErrorAction Stop
            # -ErrorAction Stop: Get-Content's default ErrorActionPreference lets a read
            # failure (permission denied, file locked) emit a non-terminating error and
            # continue past this try/catch with $ca_pem still $null, which the next
            # check below would then misreport as "empty" rather than the real cause.
            $ca_pem = Get-Content -Path $ca_snapshot -Raw -ErrorAction Stop
        } catch {
            $ca_reject_reason = "could not be read ($($_.Exception.Message))"
        }
    }

    # Cheap bound before ever parsing it: empty or implausibly large for a CA
    # certificate is rejected the same way a malformed one is.
    if (-Not $ca_reject_reason -and ([string]::IsNullOrEmpty($ca_pem) -or $ca_pem.Length -gt 65536)) {
        $ca_reject_reason = "is empty or larger than the 64 KiB a CA certificate should ever need"
    }

    # A manager delivery is expected to be exactly one self-signed root, never a
    # bundle/chain -- reject that shape explicitly. Left unchecked, the global
    # -replace below would strip every BEGIN/END marker in a multi-cert file
    # and concatenate all their bodies into one blob, unlike openssl x509 on
    # the Linux/macOS side, which silently parses only the first certificate
    # and ignores the rest; explicit rejection here keeps both platforms
    # consistent instead of diverging on this input shape.
    if (-Not $ca_reject_reason) {
        $begin_marker_count = ([regex]::Matches($ca_pem, '-----BEGIN CERTIFICATE-----')).Count
        if ($begin_marker_count -gt 1) {
            $ca_reject_reason = "contains more than one certificate (expected exactly one self-signed root)"
        }
    }

    if (-Not $ca_reject_reason) {
        try {
            # Extract strictly between the first BEGIN/END pair, not just delete the
            # marker strings from the whole content: openssl's own PEM reader does the
            # same (scans for the markers, ignores anything outside them), so a file
            # with a readable preamble before BEGIN -- valid PEM, and accepted on the
            # Linux/macOS side -- would otherwise leave that preamble text mixed into
            # $ca_base64 here and fail to decode.
            $pem_match = [regex]::Match($ca_pem, '-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', [System.Text.RegularExpressions.RegexOptions]::Singleline)
            if (-Not $pem_match.Success) {
                throw "no BEGIN/END CERTIFICATE block found"
            }
            $ca_base64 = ($pem_match.Groups[1].Value -replace '[\r\n\s]', '')
            $ca_bytes = [System.Convert]::FromBase64String($ca_base64)
            # New-Object, not the ::new() static-method syntax: ::new() requires
            # PowerShell 5.0+ and this script otherwise targets much older hosts (see
            # Start-NativePowerShell's "Windows PowerShell v1.0" path above) -- on an
            # older PowerShell, ::new() would fail to parse and every valid CA would be
            # rejected here as "does not parse as a PEM certificate". The leading comma
            # stops New-Object from unrolling the byte array into multiple constructor
            # arguments.
            $ca_cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $ca_bytes)
        } catch {
            $ca_reject_reason = "does not parse as a PEM certificate ($($_.Exception.Message))"
        }
    }

    if (-Not $ca_reject_reason) {
        $basic_constraints = $ca_cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] } | Select-Object -First 1
        if (-Not $basic_constraints -or -Not $basic_constraints.CertificateAuthority) {
            $ca_reject_reason = "is not a CA certificate (no Basic Constraints CA:TRUE)"
        }
    }

    if (-Not $ca_reject_reason) {
        $now = Get-Date
        if ($now -lt $ca_cert.NotBefore) {
            $ca_reject_reason = "is not yet valid (notBefore $($ca_cert.NotBefore))"
        } elseif ($now -gt $ca_cert.NotAfter) {
            $ca_reject_reason = "has expired (notAfter $($ca_cert.NotAfter))"
        }
    }

    if ($ca_reject_reason) {
        # A malformed/expired/non-CA file must not break the upgrade, nor be left behind
        # for a later upgrade to pick up -- remove it below same as on success.
        Write-Output "$(Get-Date -format u) - Delivered CA at $($incoming_ca_file) $($ca_reject_reason); refusing to install it and continuing without it." >> .\upgrade\upgrade.log
    } else {
        # Written only once the remaining gates have passed (see below).
        $ca_validated = $true
        Write-Output "$(Get-Date -format u) - Delivered CA at $($incoming_ca_file) is valid; holding it until this script's remaining checks pass, then installing it at $($default_ca_file)." >> .\upgrade\upgrade.log
    }

    # $ca_pem carries the validated content from here on, so only the delivered file
    # is kept: it lets an aborted upgrade retry against the same delivery.
    Remove-Item -Force -ErrorAction SilentlyContinue $ca_snapshot
    if (-Not $ca_validated) {
        Remove-Item -Force -ErrorAction SilentlyContinue $incoming_ca_file
    }
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

function probe_tcp($server, $port) {
    # Match the socket family to the resolved address so an IPv6-only manager is still reachable.
    $family = [System.Net.Sockets.AddressFamily]::InterNetwork
    try {
        $addr = [System.Net.Dns]::GetHostAddresses($server) | Select-Object -First 1
        if ($addr) { $family = $addr.AddressFamily }
    } catch { }
    $client = New-Object System.Net.Sockets.TcpClient($family)
    try {
        $result = $client.BeginConnect($server, $port, $null, $null)
        return $result.AsyncWaitHandle.WaitOne(5000) -and $client.Connected
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

# Check the manager is up: GET /<endpoint>/ is remoted's health endpoint and answers 200 -- the
# request must include the manager's reverse-proxy prefix (#38492/#38491) or it 404s. A TLS
# handshake failure falls back to a TCP-only check, since older hosts can't negotiate the
# manager's TLS 1.3 minimum (#38607); any non-TLS error is a real "not reachable".
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
        if ($_.Exception -is [System.Net.WebException] -and $_.Exception.Status -eq [System.Net.WebExceptionStatus]::SecureChannelFailure) {
            write-output "$(Get-Date -format u) - HTTPS handshake failed (host may lack TLS 1.3), falling back to a TCP connectivity check (manager endpoint not verified)." >> .\upgrade\upgrade.log
            return probe_tcp $server $port
        }
        return $false
    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $saved_callback
    }
}

# Same target as probe_server(), but with the OS's own certificate validation instead
# of WazuhProbeTrust::Always: succeeds only if the system trust store actually
# verifies the manager's certificate. probe_server() cannot tell us this, since it
# deliberately accepts any certificate so a plain reachability check never depends on
# TLS trust -- but it is exactly what AGENT_VERIFY_SYSTEM needs to work post-upgrade.
function probe_server_verified($server, $port, $endpoint) {
    $saved_callback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
        $path = if ([string]::IsNullOrEmpty($endpoint)) { "/" } else { "/$endpoint/" }

        $host_part = $server
        if ($host_part.Contains(":") -And -Not $host_part.StartsWith("[")) {
            $host_part = "[$host_part]"
        }

        $response = Invoke-WebRequest -Uri "https://$($host_part):$($port)$($path)" -UseBasicParsing -TimeoutSec 5
        return ($response.StatusCode -eq 200)
    } catch {
        # Both a real cert-trust failure and an unrelated hiccup (DNS, timeout) land here as
        # the same $false, since probe_server() already confirmed reachability moments ago
        # and this function's only job is the trust decision -- but log which one it was, so
        # upgrade.log doesn't read "certificate not trusted" for a transient network blip.
        if ($_.Exception -is [System.Net.WebException] -and $_.Exception.Status -eq [System.Net.WebExceptionStatus]::SecureChannelFailure) {
            write-output "$(Get-Date -format u) - Certificate trust check failed: the system trust store does not verify the manager's certificate ($($_.Exception.Message))." >> .\upgrade\upgrade.log
        } else {
            write-output "$(Get-Date -format u) - Certificate trust check failed for a reason other than certificate trust ($($_.Exception.GetType().Name): $($_.Exception.Message)); treating as not verified." >> .\upgrade\upgrade.log
        }
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
} else {
    $probe_ok = $false
    for ($i = 0; $i -lt 3; $i++) {
        if (probe_server $server_address $server_port $server_endpoint) {
            $probe_ok = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-Not $probe_ok) {
        write-output "$(Get-Date -format u) - Upgrade failed: the manager is not reachable at $($server_address):$($server_port) (endpoint: '$($server_endpoint)'), interrupting upgrade." >> .\upgrade\upgrade.log
        abort_upgrade "2"
    } else {
        write-output "$(Get-Date -format u) - Manager reachable at $($server_address):$($server_port) (endpoint: '$($server_endpoint)')." >> .\upgrade\upgrade.log
    }
}

# The upgrade replaces the agent's binaries but not its ossec.conf, so the TLS
# posture the new agent boots under is exactly what's on disk now. A verifying mode
# with no readable CA can never connect -- mirrors
# w_agent_validate_ssl_ca() in config.c -- so catch it here, before the old agent
# is gone, rather than leaving a freshly-upgraded host silently offline.
$ssl_verification_mode = get_conf_value "agent" "ssl" "verification_mode"
$ssl_ca = get_conf_value "agent" "ssl" "certificate_authorities"
$ssl_verification_mode_explicit = ($null -ne $ssl_verification_mode)

if ([string]::IsNullOrEmpty($ssl_verification_mode)) {
    if ($ssl_verification_mode_explicit) {
        # <verification_mode/> (or <verification_mode></verification_mode>) is present but
        # carries no value -- get_conf_value already distinguishes this from "absent" ($null
        # vs ""), but Read_Agent_SSL() rejects empty content as an unrecognized value
        # (XML_VALUEERR) same as any other typo. Treat it the same way here instead of
        # silently substituting the default on a config the new binary is about to refuse
        # to parse.
        write-output "$(Get-Date -format u) - Upgrade failed: <ssl><verification_mode> is present but empty, interrupting upgrade." >> .\upgrade\upgrade.log
        abort_upgrade "2"
    } elseif ([string]::IsNullOrEmpty($ssl_ca)) {
        $ssl_verification_mode = "system"
    } else {
        $ssl_verification_mode = "certificate"
    }
}

# Same path as AGENT_ANCHOR_CA (src/shared/include/defs.h), which the agent now reads
# directly: a present, readable file here supplies the verification state for anything
# <ssl> left unsaid, so the resolution this gate mirrors above is no longer the one the
# upgraded binary applies: an unset <verification_mode> resolves to 'full' with the anchor
# present and 'none' without it, never to this gate's 'system'. An explicit mode is
# honoured unchanged, 'none' included, so the divergence is in the unset and
# no-readable-CA rows only. Reconciling the rest is still open; no verdict below was
# changed for it, but the state that drives the divergence is logged.

# One already on disk and one validated this run but not yet written reach the same
# post-upgrade state, so the checks below ask this instead of testing the file.
$anchor_available = (Test-Path -PathType Leaf $default_ca_file) -or $ca_validated

if ($anchor_available) {
    write-output "$(Get-Date -format u) - A trust anchor will be in place at $($default_ca_file) for the upgraded agent. It verifies with 'full' against that file when <ssl> names no <verification_mode>, and uses it as the default <certificate_authorities>. An explicit <verification_mode> is honoured unchanged." >> .\upgrade\upgrade.log
} else {
    # No anchor at all -- neither delivered this run nor left over from a previous
    # one -- and <ssl> left unset resolves to unverified without it. Say so plainly,
    # since this is the one remaining path to an unverified 5.0 agent and it must be
    # obvious, not silent.
    write-output "$(Get-Date -format u) - No trust anchor is present at $($default_ca_file); the upgraded agent will run unverified unless <ssl><verification_mode> and <certificate_authorities> are configured explicitly. To enable verification: place the manager's CA at $($default_ca_file) and re-run the upgrade, or configure <certificate_authorities> explicitly and restart the agent." >> .\upgrade\upgrade.log
}

# Whether the currently-installed (pre-upgrade) agent predates 5.0, read from
# $current_version above (captured before the MSI replaces VERSION.json). A genuine
# 4.x config is always <client>-only -- Read_Legacy_Client_Address() (config.c) never
# reads <ssl> under <client> -- so that agent cannot express TLS verification via
# ossec.conf, edit or not. It also does not need to for safety: under implicit
# 'system' mode, w_agent_validate_ssl_ca() (config.c) only refuses to start when no OS
# CA bundle exists at all, never when that bundle simply fails to verify this
# particular manager -- so letting a legacy upgrade proceed past that specific failure
# below does not risk the fail-closed outage this gate exists to prevent. An
# already-5.x agent gets no such pass: it has had every chance to be configured
# correctly, so the strict check remains in force for it. Mirrors pkg_installer.sh's
# IS_LEGACY_AGENT.
$is_legacy_agent = $false
try {
    $current_ver_parsed = [Version]($current_version -replace '^v', '')
    if ($current_ver_parsed.Major -lt 5) {
        $is_legacy_agent = $true
    }
} catch {
    # Unparsable -- never assume legacy from a guess.
}

if ($ssl_verification_mode -ceq "full" -or $ssl_verification_mode -ceq "certificate") {
    if ([string]::IsNullOrEmpty($ssl_ca) -or -Not (Test-Path -PathType Leaf $ssl_ca)) {
        write-output "$(Get-Date -format u) - Upgrade failed: <ssl><verification_mode> is '$($ssl_verification_mode)' but <certificate_authorities> ('$($ssl_ca)') is missing or unreadable, interrupting upgrade." >> .\upgrade\upgrade.log
        abort_upgrade "2"
    }
} elseif ($ssl_verification_mode -ceq "system") {
    # verification_mode=system with a certificate_authorities also set is rejected
    # outright at runtime (validateTls() in moduleConfig.cpp) regardless of whether
    # the manager's certificate happens to verify against the OS store -- catch the
    # config error itself here rather than let a live probe that happens to pass mask
    # a daemon that will refuse to start.
    if (-Not [string]::IsNullOrEmpty($ssl_ca)) {
        write-output "$(Get-Date -format u) - Upgrade failed: <ssl><verification_mode> is 'system' but <certificate_authorities> ('$($ssl_ca)') is also set; 'system' trusts the OS store, not a configured CA, and the agent refuses to start with both set. Remove <certificate_authorities>, or switch to <verification_mode>certificate</verification_mode>, interrupting upgrade." >> .\upgrade\upgrade.log
        abort_upgrade "2"
    }

    # 'system' trusts the OS store, not a configured CA -- probe_server() above cannot
    # tell us whether that store actually trusts THIS manager's certificate, since it
    # deliberately accepts any certificate so the plain reachability check never
    # depends on TLS trust. Find out for real before assuming the freshly-upgraded
    # agent will still be able to connect.
    if ($env:WAZUH_UPGRADE_TEST_SKIP_MANAGER_CHECK -eq "1") {
        write-output "$(Get-Date -format u) - System CA trust check skipped (test mode)." >> .\upgrade\upgrade.log
    } elseif (probe_server_verified $server_address $server_port $server_endpoint) {
        write-output "$(Get-Date -format u) - The system trust store already verifies the manager's certificate; proceeding under verify_mode=system." >> .\upgrade\upgrade.log
    } elseif ($ssl_verification_mode_explicit) {
        # <verification_mode>system</verification_mode> was set explicitly: pinning a
        # CA here would be rejected at runtime (validateTls() in moduleConfig.cpp
        # refuses system+certificate_authorities together), so there is nothing this
        # script can safely fix on the operator's behalf.
        write-output "$(Get-Date -format u) - Upgrade failed: <ssl><verification_mode> is explicitly 'system' but the system trust store does not verify the manager's certificate at $($server_address):$($server_port). Import it into the OS trust store, or switch to <verification_mode>certificate</verification_mode> with a <certificate_authorities> path, interrupting upgrade." >> .\upgrade\upgrade.log
        abort_upgrade "2"
    } elseif ($anchor_available) {
        # <verification_mode> was left unset (not explicit), so the new binary resolves
        # purely from anchor presence -- 'full' against $default_ca_file -- regardless
        # of what this gate's own 'system' resolution or the OS trust store say. A
        # usable anchor is available (validated this run and installed once the gates
        # pass, or left over from a previous delivery), which is a different, equally
        # sufficient path to a working post-upgrade connection -- this is precisely the
        # scenario this feature exists for. Checked ahead of $is_legacy_agent since an
        # already-5.x agent needs this path too: without it, a 5.x agent receiving its
        # manager's CA for the first time would have the anchor installed and then
        # abort anyway, never reaching a state where it takes effect.
        write-output "$(Get-Date -format u) - The system trust store does not verify the manager's certificate at $($server_address):$($server_port), but a trust anchor is present at $($default_ca_file) and <ssl><verification_mode> is unset -- the upgraded agent resolves to 'full' against that anchor regardless of the OS trust store, so proceeding." >> .\upgrade\upgrade.log
    } elseif ($is_legacy_agent) {
        # The currently-installed agent (pre-upgrade) predates 5.0: its <client>-only
        # config cannot express TLS verification regardless of what this script does
        # (see $is_legacy_agent above), and 'system' mode's real fail-closed condition
        # -- no OS CA bundle at all -- does not apply here. Proceed rather than block
        # a legacy migration over a check that agent was never able to pass in the
        # first place.
        write-output "$(Get-Date -format u) - The system trust store does not verify the manager's certificate at $($server_address):$($server_port), but the currently-installed agent ($($current_version)) predates 5.0 and its config cannot express TLS verification either way -- proceeding unverified. No trust anchor is present at $($default_ca_file); place one there and re-run the upgrade, or configure <certificate_authorities> explicitly after the upgrade, to enable verification." >> .\upgrade\upgrade.log
    } else {
        # Reached only when no usable anchor is present at all (the branch above
        # already handles the case where one is) -- ossec.conf is never modified by
        # this script, so there is genuinely nothing more it can do here.
        write-output "$(Get-Date -format u) - Upgrade failed: the system trust store does not verify the manager's certificate at $($server_address):$($server_port), and no trust anchor is present at $($default_ca_file). Place the manager's CA there and retry, or configure <certificate_authorities> explicitly; interrupting upgrade." >> .\upgrade\upgrade.log
        abort_upgrade "2"
    }
} elseif ($ssl_verification_mode -ceq "none") {
    # Nothing for this gate to check: 'none' needs no CA and reaches no trust store, and the
    # upgraded binary honours it whether or not an anchor is on disk.
} else {
    # Neither ReadConfig() nor this gate's own default-resolution above can produce
    # anything but full/certificate/system/none, so getting here means ossec.conf carries
    # something else (a typo, hand-edited garbage). Read_Agent_SSL() rejects that value
    # too, so letting the upgrade proceed would just trade this loud failure for the new
    # binary refusing to start after the old one is already gone.
    write-output "$(Get-Date -format u) - Upgrade failed: <ssl><verification_mode> is '$($ssl_verification_mode)', which is not a value this agent recognizes (full, certificate, system, or none); interrupting upgrade." >> .\upgrade\upgrade.log
    abort_upgrade "2"
}

# Installed only past the last gate that can abort: with <verification_mode> unset the
# anchor's mere presence flips the agent to 'full' on its next restart, so writing it
# earlier left an aborted upgrade with a changed trust posture on the old version.
if ($ca_validated) {
    # An operator can point <certificate_authorities> at this exact default path
    # themselves (rather than relying on manager delivery) -- comparing resolved
    # paths where possible, since the config value and $default_ca_file are rarely
    # written the same way (relative vs. absolute) even when they name the same
    # file. Overwriting still proceeds either way (the manager is authoritative
    # for its own CA), but a collision with an operator's own explicit pin is a
    # more consequential event than routine anchor rotation and deserves its own,
    # louder log line rather than reading identically to one.
    $operator_ca_path = get_conf_value "agent" "ssl" "certificate_authorities"
    $ca_pinned_here = $false
    if (-Not [string]::IsNullOrEmpty($operator_ca_path)) {
        try {
            $resolved_operator = (Resolve-Path -ErrorAction Stop $operator_ca_path).Path
            $resolved_default = (Resolve-Path -ErrorAction Stop $default_ca_file).Path
            if ($resolved_operator -eq $resolved_default) {
                $ca_pinned_here = $true
            }
        } catch {
            if ($operator_ca_path -eq $default_ca_file) {
                $ca_pinned_here = $true
            }
        }
    }

    # Replacing an already-present anchor is a bigger event than a first install --
    # the manager is authoritative for its own CA, so this always proceeds, but the
    # operator should be able to grep for the distinction rather than see the same
    # "Installed" line either way.
    if ($ca_pinned_here) {
        $ca_install_verb = "Overwrote the operator-pinned (<certificate_authorities>$($operator_ca_path)</certificate_authorities>)"
    } elseif (Test-Path -PathType Leaf $default_ca_file) {
        $ca_install_verb = "Replaced the existing"
    } else {
        $ca_install_verb = "Installed the delivered"
    }

    New-Item -ItemType Directory -Force -Path (Split-Path $default_ca_file) | Out-Null

    # Install atomically: write to a temp file in the same directory, then move it
    # over the target, so a reader never observes a partially-written anchor, and a
    # failed write is caught here instead of silently logging success with nothing
    # actually installed.
    $ca_install_ok = $true
    $ca_tmp_file = "$($default_ca_file).tmp"
    try {
        Set-Content -Path $ca_tmp_file -Value $ca_pem -NoNewline -ErrorAction Stop
        Move-Item -Force -Path $ca_tmp_file -Destination $default_ca_file -ErrorAction Stop
    } catch {
        Write-Output "$(Get-Date -format u) - Could not install the delivered CA at $($default_ca_file) (write failure: $($_.Exception.Message)); leaving any existing anchor untouched and continuing the upgrade." >> .\upgrade\upgrade.log
        Remove-Item -Force -ErrorAction SilentlyContinue $ca_tmp_file
        $ca_install_ok = $false
    }

    if ($ca_install_ok) {
        # Deny Authenticated Users on this one file, same intent as the pattern
        # already used for client.keys/authd.pass (InstallerScripts.vbs) -- but
        # implemented differently: the install directory's S-1-5-11 grant that
        # applies to a freshly-created file here is inherited, not explicit, and
        # icacls's plain /remove only strips explicit ACEs -- it silently leaves
        # an inherited one in place and still reports success. Breaking
        # inheritance (/inheritance:r) and re-granting only Administrators/SYSTEM
        # explicitly (:r replaces rather than appends, so a re-run doesn't
        # duplicate entries) actually removes Authenticated Users' access. This only
        # covers the window before the MSI: SetWazuhPermissions resets the install
        # directory's ACLs, so the lasting state of this file is set there instead.
        try {
            icacls "$default_ca_file" /inheritance:r /grant:r "*S-1-5-32-544:(F)" "*S-1-5-18:(F)" /q | Out-Null
            # icacls is an external process: a non-zero exit code is not a
            # PowerShell exception and would not otherwise be caught below --
            # check $LASTEXITCODE explicitly rather than assume success.
            if ($LASTEXITCODE -ne 0) {
                Write-Output "$(Get-Date -format u) - Could not restrict permissions on $($default_ca_file): icacls exited with code $($LASTEXITCODE)." >> .\upgrade\upgrade.log
            }
        } catch {
            Write-Output "$(Get-Date -format u) - Could not restrict permissions on $($default_ca_file): $($_.Exception.Message)" >> .\upgrade\upgrade.log
        }

        # A present, readable anchor here is picked up automatically at agent startup
        # and resolves an unset <verification_mode> to 'full' against it -- so this
        # alone is sufficient to activate verification; no <ssl> edit is needed.
        Write-Output "$(Get-Date -format u) - $($ca_install_verb) CA at $($default_ca_file). ossec.conf is not modified, but this alone is sufficient to activate certificate verification: the agent resolves an unset <verification_mode> to 'full' against a present, readable anchor at this path." >> .\upgrade\upgrade.log
    }

    Remove-Item -Force -ErrorAction SilentlyContinue $incoming_ca_file
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
