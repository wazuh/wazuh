SETLOCAL EnableExtensions
SET PATH=%PATH%;C:\Program Files\Microsoft SDKs\Windows\v7.0\Bin
SET PATH=%PATH%;C:\Program Files (x86)\WiX Toolset v3.11\bin

REM Fix all .exe and .dll files
call :sign "*.exe"
call :sign "..\*.dll"
call :sign "*.dll"
call :sign "..\data_provider\build\bin\sysinfo.dll"
call :sign "..\shared_modules\dbsync\build\bin\dbsync.dll"
call :sign "..\shared_modules\rsync\build\bin\rsync.dll"
call :sign "..\wazuh_modules\syscollector\build\bin\syscollector.dll"
call :sign "..\syscheckd\build\bin\libfimdb.dll"
call :sign "InstallerScripts.vbs"
pause
EXIT /B 0

:sign
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 %1
if %ERRORLEVEL% NEQ 0 (
    echo SignTool Error: signing failed for %1 with exit code %ERRORLEVEL%
    EXIT /B 1
)
EXIT /B 0
