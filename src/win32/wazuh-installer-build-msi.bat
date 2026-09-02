SETLOCAL
SET PATH=%PATH%;C:\Program Files\Microsoft SDKs\Windows\v7.0\Bin
SET PATH=%PATH%;C:\Program Files (x86)\WiX Toolset v3.11\bin

set VERSION=%1
set REVISION=%2

REM IF VERSION or REVISION are empty, ask for their value
IF [%VERSION%] == [] set /p VERSION=Enter the version of the Wazuh agent (x.y.z):
IF [%REVISION%] == [] set /p REVISION=Enter the revision of the Wazuh agent:

SET MSI_NAME=wazuh-agent-%VERSION%-%REVISION%.msi

candle.exe -nologo "wazuh-installer.wxs" -out "wazuh-installer.wixobj" -ext WixUtilExtension -ext WixUiExtension
if %ERRORLEVEL% NEQ 0 (
    echo candle.exe failed with exit code %ERRORLEVEL%
    EXIT /B 1
)
light.exe "wazuh-installer.wixobj" -out "%MSI_NAME%"  -ext WixUtilExtension -ext WixUiExtension
if %ERRORLEVEL% NEQ 0 (
    echo light.exe failed with exit code %ERRORLEVEL%
    EXIT /B 1
)

signtool sign /a /tr http://timestamp.digicert.com /fd SHA256 /d "%MSI_NAME%" /td SHA256 "%MSI_NAME%"
if %ERRORLEVEL% NEQ 0 (
    echo SignTool Error: signing failed for %MSI_NAME% with exit code %ERRORLEVEL%
    EXIT /B 1
)

signtool verify /v /pa "%MSI_NAME%"
if %ERRORLEVEL% NEQ 0 (
    echo SignTool Error: signature verification failed for %MSI_NAME% with exit code %ERRORLEVEL%
    EXIT /B 1
)

pause
