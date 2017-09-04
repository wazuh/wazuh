@ECHO off

IF "%1"=="B" GOTO background

START /B upgrade\upgrade.bat B
GOTO end

:background
SLEEP 5 2> NUL || ping -n 5 127.0.0.1 > NUL
powershell -ExecutionPolicy ByPass -File upgrade\do_upgrade.ps1

:end
