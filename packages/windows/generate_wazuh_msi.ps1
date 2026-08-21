# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

param (
    [string]$MSI_NAME = "wazuh-agent.msi",
    [string]$SIGN = "no",
    [string]$WIX_TOOLS_PATH = "",
    [string]$SIGN_TOOLS_PATH = "",
    [string]$CERTIFICATE_PATH = "",
    [string]$CERTIFICATE_PASSWORD = "",
    [string]$DLIB_PATH = "",
    [string]$DLIB_METADATA = "",
    [switch]$help
    )

$CANDLE_EXE = "candle.exe"
$LIGHT_EXE = "light.exe"
$SIGNTOOL_EXE = "signtool.exe"

if(($help.isPresent)) {
    "
    This tool can be used to generate the Windows Wazuh agent msi package.

    PARAMETERS TO BUILD WAZUH-AGENT MSI (OPTIONALS):
        1. MSI_NAME: MSI package name output.
        2. SIGN: yes or no. By default 'no'.
        3. WIX_TOOLS_PATH: Wix tools path.
        4. SIGN_TOOLS_PATH: sign tools path.
        5. CERTIFICATE_PATH: Path to the .pfx certificate file.
        6. CERTIFICATE_PASSWORD: Password for the .pfx certificate file.
        7. DLIB_PATH: Full path to the x64 Azure.CodeSigning.Dlib.dll from the Artifact Signing Client Tools
           (e.g. C:\Program Files\Artifact Signing Client Tools\bin\x64\Azure.CodeSigning.Dlib.dll).
           Overrides CERTIFICATE_PATH/`/a` when set together with DLIB_METADATA.
        8. DLIB_METADATA: Path to the dlib metadata.json (Endpoint/CodeSigningAccountName/CertificateProfileName).

    USAGE:

        * WAZUH:
          $ ./generate_wazuh_msi.ps1  -MSI_NAME {{ NAME }} -SIGN {{ yes|no }} -WIX_TOOLS_PATH {{ PATH }} -SIGN_TOOLS_PATH {{ PATH }}
            Build a devel msi:    $ ./generate_wazuh_msi.ps1 -MSI_NAME wazuh-agent_4.9.0-0_windows_0ceb378.msi -SIGN no
            Build a prod msi:     $ ./generate_wazuh_msi.ps1 -MSI_NAME wazuh-agent-4.9.0-1.msi -SIGN yes
    "
    Exit
}

# Get Power Shell version.
$PSversion = $PSVersionTable.PSVersion.Major
if ($PSversion -eq $null) {
    $PSversion = 1 # $PSVersionTable is new with Powershell 2.0
}

function BuildWazuhMsi(){
    Write-Host "MSI_NAME = $MSI_NAME"

    if($WIX_TOOLS_PATH -ne ""){
        $CANDLE_EXE = $WIX_TOOLS_PATH + "/" + $CANDLE_EXE
        $LIGHT_EXE = $WIX_TOOLS_PATH + "/" + $LIGHT_EXE
    }

    if($SIGN_TOOLS_PATH -ne ""){
        $SIGNTOOL_EXE = $SIGN_TOOLS_PATH + "/" + $SIGNTOOL_EXE
    }

    if($SIGN -eq "yes"){
        $signOptions = @()
        $tsaUrl = "http://timestamp.digicert.com"
        if ($DLIB_PATH -ne "" -and $DLIB_METADATA -ne "") {
            $signOptions += "/dlib"
            $signOptions += "`"$DLIB_PATH`""
            $signOptions += "/dmdf"
            $signOptions += "`"$DLIB_METADATA`""
            $tsaUrl = "http://timestamp.acs.microsoft.com"
        } elseif ($CERTIFICATE_PATH -ne "" -and $CERTIFICATE_PASSWORD -ne "") {
            $signOptions += "/f"
            $signOptions += "`"$CERTIFICATE_PATH`""
            $signOptions += "/p"
            $signOptions += "`"$CERTIFICATE_PASSWORD`""
        } else {
            $signOptions += "/a"
        }

        # Define files to sign
        $filesToSign = @(
            ".\*.exe",
            ".\InstallerScripts.vbs",
            "..\*.dll",
            ".\*.dll",
            "..\data_provider\build\bin\sysinfo.dll",
            "..\shared_modules\dbsync\build\bin\dbsync.dll",
            "..\shared_modules\rsync\build\bin\rsync.dll",
            "..\wazuh_modules\syscollector\build\bin\syscollector.dll",
            "..\syscheckd\build\bin\libfimdb.dll"
        )

        # Expand each pattern ourselves so a zero-match glob is a deliberate skip,
        # not an ambiguous signtool exit code.
        foreach ($pattern in $filesToSign) {
            $matchedFiles = @(Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue)
            if ($matchedFiles.Count -eq 0) {
                Write-Host "No files matched $pattern, skipping."
                continue
            }
            foreach ($file in $matchedFiles) {
                Write-Host "Signing $($file.FullName)..."
                & $SIGNTOOL_EXE sign /v /debug $signOptions /tr $tsaUrl /fd SHA256 /td SHA256 $file.FullName
                if ($LASTEXITCODE -ne 0) {
                    throw "SignTool Error: signing failed for $($file.FullName) (exit code $LASTEXITCODE)"
                }
            }
        }
    }

    Write-Host "Building MSI installer..."

    & $CANDLE_EXE -nologo .\wazuh-installer.wxs -out "wazuh-installer.wixobj" -ext WixUtilExtension -ext WixUiExtension
    if ($LASTEXITCODE -ne 0) {
        throw "candle.exe failed with exit code $LASTEXITCODE"
    }
    & $LIGHT_EXE ".\wazuh-installer.wixobj" -out $MSI_NAME -ext WixUtilExtension -ext WixUiExtension
    if ($LASTEXITCODE -ne 0) {
        throw "light.exe failed with exit code $LASTEXITCODE"
    }

    if($SIGN -eq "yes"){
        Write-Host "Signing $MSI_NAME..."
        & $SIGNTOOL_EXE sign /v /debug $signOptions /tr $tsaUrl /d $MSI_NAME /fd SHA256 /td SHA256 $MSI_NAME
        if ($LASTEXITCODE -ne 0) {
            throw "SignTool Error: signing failed for $MSI_NAME (exit code $LASTEXITCODE)"
        }

        Write-Host "Verifying $MSI_NAME signature..."
        & $SIGNTOOL_EXE verify /v /debug /pa $MSI_NAME
        if ($LASTEXITCODE -ne 0) {
            throw "SignTool Error: signature verification failed for $MSI_NAME (exit code $LASTEXITCODE)"
        }
    }
}

function ExtractDebugSymbols(){

	#all executables in current folder
	$exeFiles = Get-ChildItem -Filter "*.exe"
	$exeFiles += Get-ChildItem -Filter "*.dll" 

	#all executables in parent folder
	cd .. #Get-ChildItem does not take "..\" so we have to do it manually
	$exeFiles += Get-ChildItem -Filter "*.dll"

	#plus a few more individual libraries
	$exeFiles +=  Get-ChildItem -Filter "data_provider\build\bin\sysinfo.dll"
	$exeFiles +=  Get-ChildItem -Filter "shared_modules\dbsync\build\bin\dbsync.dll"
	$exeFiles +=  Get-ChildItem -Filter "shared_modules\rsync\build\bin\rsync.dll"
	$exeFiles +=  Get-ChildItem -Filter "wazuh_modules\syscollector\build\bin\syscollector.dll"
	$exeFiles +=  Get-ChildItem -Filter "syscheckd\build\bin\libfimdb.dll"
	cd "win32"

	#now loop
	foreach ($file in $exeFiles)
	{
		Write-Host "Extracting dbg symbols from" $file.FullName
		$args = $file.FullName #source (exe/dll with debug symbols)
		$args += " "
		$args += $file.FullName  #destination (same as source - exe/dll is stripped of debug symbols)
		$args += " "
		$args += $file.BaseName
		$args += ".pdb"

		Start-Process -FilePath "cv2pdb.exe" -ArgumentList $args -WindowStyle Hidden
	}

  Write-Host "Waiting for processes to finish"
  Wait-Process -Name cv2pdb -Timeout 10

  #compress every pdb file in current folder
	$pdbFiles = Get-ChildItem -Filter ".\*.pdb"

    $ZIP_NAME = $MSI_NAME -replace 'wazuh-agent', 'wazuh-agent-debug-symbols' -replace '\.msi$', '.zip'

	Write-Host "Compressing debug symbols to $ZIP_NAME"
	Compress-Archive -Path $pdbFiles -Force -DestinationPath "$ZIP_NAME"

	Remove-Item -Path "*.pdb"
}

############################
# MAIN
############################

ExtractDebugSymbols
BuildWazuhMsi
