# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

param (
    [string]$MSI_NAME = "wazuh-agent.msi",
    [string]$SIGN = "no",
    [string]$WIX_TOOLS_PATH = "",
    [string]$SIGN_TOOLS_PATH = "",
    [string]$CERTIFICATE_PATH = "",
    [string]$CERTIFICATE_PASSWORD = "",
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
        # Determine signing command options
        $signOptions = @()
        if ($CERTIFICATE_PATH -ne "" -and $CERTIFICATE_PASSWORD -ne "") {
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
            "..\wazuh_modules\syscollector\build\bin\sca.dll",
            "..\syscheckd\build\bin\libfimdb.dll"
        )

        # Sign the files
        foreach ($file in $filesToSign) {
            Write-Host "Signing $file..."
            & $SIGNTOOL_EXE sign $signOptions /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 $file
        }
    }

    Write-Host "Building MSI installer..."

    & $CANDLE_EXE -nologo .\wazuh-installer.wxs -out "wazuh-installer.wixobj" -ext WixUtilExtension -ext WixUiExtension
    & $LIGHT_EXE ".\wazuh-installer.wixobj" -out $MSI_NAME -ext WixUtilExtension -ext WixUiExtension

    if($SIGN -eq "yes"){
        Write-Host "Signing $MSI_NAME..."
        & $SIGNTOOL_EXE sign $signOptions /tr http://timestamp.digicert.com /d $MSI_NAME /fd SHA256 /td SHA256 $MSI_NAME
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
    $exeFiles +=  Get-ChildItem -Filter "wazuh_modules\sca\build\bin\sca.dll"
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
