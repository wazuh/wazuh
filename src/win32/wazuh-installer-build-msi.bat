@echo off
SETLOCAL
SET PATH=%PATH%;C:\Program Files\Microsoft SDKs\Windows\v7.0\Bin
SET PATH=%PATH%;C:\Program Files (x86)\WiX Toolset v3.11\bin

set VERSION=%1
set REVISION=%2
set ARCH=%3

REM IF VERSION or REVISION are empty, ask for their value
IF [%VERSION%] == [] set /p VERSION=Enter the version of the Wazuh agent (x.y.z):
IF [%REVISION%] == [] set /p REVISION=Enter the revision of the Wazuh agent:

REM IF ARCH is empty or invalid, ask for its value
IF [%ARCH%] == [] goto :AskArch
IF [%ARCH%] == [x86] goto :GenerateMSI
IF [%ARCH%] == [x86_64] goto :GenerateMSI

:AskArch
set /p ARCH=Choose the architecture for the output MSI (x86 / x86_64):
IF [%ARCH%] == [x86] goto :GenerateMSI
IF [%ARCH%] == [x86_64] goto :GenerateMSI
echo Incorrect input
goto :AskArch

:GenerateMSI
SET MSI_NAME=wazuh-agent-%VERSION%-%REVISION%-%ARCH%.msi

REM Change WiX command line based on the selected architecture
if [%ARCH%] == [x86] (
  candle.exe -arch x86 -dDestInstallDir=ProgramFilesFolder -nologo "wazuh-installer.wxs" -out "wazuh-installer.wixobj" -ext WixUtilExtension -ext WixUiExtension
) else (
  candle.exe -arch x64 -dDestInstallDir=ProgramFiles64Folder -nologo "wazuh-installer.wxs" -out "wazuh-installer.wixobj" -ext WixUtilExtension -ext WixUiExtension
)

light.exe "wazuh-installer.wixobj" -out "%MSI_NAME%" -ext WixUtilExtension -ext WixUiExtension

signtool sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /d "%MSI_NAME%" /td SHA256 "%MSI_NAME%"

pause
