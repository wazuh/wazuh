SETLOCAL
SET PATH=%PATH%;C:\Program Files\Microsoft SDKs\Windows\v7.0\Bin
SET PATH=%PATH%;C:\Program Files (x86)\WiX Toolset v3.11\bin

REM Fix all .exe files
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "*.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "InstallerScripts.vbs"

pause
