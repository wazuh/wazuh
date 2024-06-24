@ECHO off

IF "%1"=="B" GOTO background

COPY upgrade\upgrade.bat . > NUL
COPY upgrade\do_upgrade.ps1 . > NUL
COPY upgrade\wazuh-agent*.msi . > NUL

START /B upgrade.bat B
GOTO end

:background
SLEEP 5 2> NUL || ping -n 5 127.0.0.1 > NUL
powershell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process powershell '-File \".\do_upgrade.ps1\"'}"

DEL upgrade.bat

:end
