SETLOCAL EnableExtensions
SET PATH=%PATH%;C:\Program Files\Microsoft SDKs\Windows\v7.0\Bin
SET PATH=%PATH%;C:\Program Files (x86)\WiX Toolset v3.11\bin

REM Fix all .exe and .dll files
call :sign "*.exe"
call :sign "..\*.dll"
call :sign "*.dll"
call :sign "..\build\bin\sysinfo.dll"
call :sign "..\build\bin\dbsync.dll"
call :sign "..\build\bin\libagent_sync_protocol.dll"
call :sign "..\build\bin\libhttps_client.dll"
call :sign "..\build\bin\schema_validator.dll"
call :sign "..\build\bin\libagent_metadata.dll"
call :sign "..\build\bin\syscollector.dll"
call :sign "..\build\bin\sca.dll"
call :sign "..\build\bin\agent_info.dll"
call :sign "..\build\bin\libfimdb.dll"
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
