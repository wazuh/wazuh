SETLOCAL
SET PATH=%PATH%;C:\Program Files\Microsoft SDKs\Windows\v7.0\Bin
SET PATH=%PATH%;C:\Program Files (x86)\WiX Toolset v3.11\bin

REM Fix all .exe and .dll files
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "*.exe"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\*.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "*.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\data_provider\build\bin\sysinfo.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\shared_modules\dbsync\build\bin\dbsync.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\shared_modules\rsync\build\bin\rsync.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\wazuh_modules\syscollector\build\bin\syscollector.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\wazuh_modules\sca\build\bin\sca.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "..\syscheckd\build\bin\libfimdb.dll"
signtool.exe sign /a /tr http://timestamp.digicert.com /fd SHA256 /td SHA256 "InstallerScripts.vbs"
pause
