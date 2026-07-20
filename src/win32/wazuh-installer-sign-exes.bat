SETLOCAL
SET PATH=%PATH%;C:\Program Files\Microsoft SDKs\Windows\v7.0\Bin
SET PATH=%PATH%;C:\Program Files (x86)\WiX Toolset v3.11\bin

REM Fix all .exe and .dll files
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "*.exe"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\*.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "*.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\build\bin\sysinfo.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\build\bin\dbsync.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\build\bin\libagent_sync_protocol.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\build\bin\schema_validator.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\build\bin\libagent_metadata.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\build\bin\syscollector.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\build\bin\sca.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\build\bin\agent_info.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\build\bin\libfimdb.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "InstallerScripts.vbs"
pause
