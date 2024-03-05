# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

param (
    [string]$OPTIONAL_REVISION = "",
    [string]$SIGN = "",
    [string]$WIX_TOOLS_PATH = "",
    [string]$SIGN_TOOLS_PATH = "",
    [switch]$help
    )

$MSI_NAME = ""
$VERSION = ""
$CANDLE_EXE = "candle.exe"
$LIGHT_EXE = "light.exe"
$SIGNTOOL_EXE = "signtool.exe"

if(($help.isPresent)) {
    "
    This tool can be used to generate the Windows Wazuh agent msi package.

    PARAMETERS TO BUILD WAZUH-AGENT MSI:
        1. OPTIONAL_REVISION: 1 or different
        2. SIGN: yes or no.
    OPTIONAL PARAMETERS:
        3. WIX_TOOLS_PATH: Wix tools path
        4. SIGN_TOOLS_PATH: sign tools path

    USAGE:

        * WAZUH:
          $ ./generate_wazuh_msi.ps1  -OPTIONAL_REVISION {{ REVISION }} -SIGN {{ yes|no }} -WIX_TOOLS_PATH {{ PATH }} -SIGN_TOOLS_PATH {{ PATH }}

            Build a devel msi:    $ ./generate_wazuh_msi.ps1 -OPTIONAL_REVISION 2 -SIGN no
            Build a prod msi:     $ ./generate_wazuh_msi.ps1 -OPTIONAL_REVISION 1 -SIGN yes -
    "
    Exit
}

# Get Power Shell version.
$PSversion = $PSVersionTable.PSVersion.Major
if ($PSversion -eq $null) {
    $PSversion = 1 # $PSVersionTable is new with Powershell 2.0
}

function ComputeMsiName() {

    ## Checking arguments
    if($OPTIONAL_REVISION -eq ""){
        Write-Host "-OPTIONAL_REVISION empty. Using default value."
        $OPTIONAL_REVISION = "1"
    }
    $VERSION = Get-Content VERSION
    $VERSION = $VERSION -replace '[v]',''

    $MSI_NAME="wazuh-agent-$VERSION-$OPTIONAL_REVISION.msi"
    return $MSI_NAME
}

function BuildWazuhMsi(){
    $MSI_NAME = ComputeMsiName
    Write-Host "MSI_NAME = $MSI_NAME"

    if($WIX_TOOLS_PATH -ne ""){
        $CANDLE_EXE = $WIX_TOOLS_PATH + "/" + $CANDLE_EXE
        $LIGHT_EXE = $WIX_TOOLS_PATH + "/" + $LIGHT_EXE
    }

    if($SIGN_TOOLS_PATH -ne ""){
        $SIGNTOOL_EXE = $SIGN_TOOLS_PATH + "/" + $SIGNTOOL_EXE
    }

    if($SIGN -eq "yes"){
        # Sign .exe files and the InstallerScripts.vbs
        Write-Host "Signing .exe files..."
        & $SIGNTOOL_EXE sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 ".\*.exe"
        Write-Host "Signing .vbs files..."
        & $SIGNTOOL_EXE sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 ".\InstallerScripts.vbs"
        Write-Host "Signing .dll files..."
        & $SIGNTOOL_EXE sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\*.dll"
        & $SIGNTOOL_EXE sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 ".\*.dll"
        & $SIGNTOOL_EXE sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\data_provider\build\bin\sysinfo.dll"
        & $SIGNTOOL_EXE sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\shared_modules\dbsync\build\bin\dbsync.dll"
        & $SIGNTOOL_EXE sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\shared_modules\rsync\build\bin\rsync.dll"
        & $SIGNTOOL_EXE sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\wazuh_modules\syscollector\build\bin\syscollector.dll"
        & $SIGNTOOL_EXE sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\syscheckd\build\bin\libfimdb.dll"
    }

    Write-Host "Building MSI installer..."

    & $CANDLE_EXE -nologo .\wazuh-installer.wxs -out "wazuh-installer.wixobj" -ext WixUtilExtension -ext WixUiExtension
    & $LIGHT_EXE ".\wazuh-installer.wixobj" -out $MSI_NAME  -ext WixUtilExtension -ext WixUiExtension

    if($SIGN -eq "yes"){
        Write-Host "Signing $MSI_NAME..."
        & $SIGNTOOL_EXE sign /a /tr http://timestamp.digicert.com /d $MSI_NAME /fd SHA256 /td SHA256 $MSI_NAME
    }
}

############################
# MAIN
############################

BuildWazuhMsi
