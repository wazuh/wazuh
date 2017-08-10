@ECHO off

IF "%1"=="B" GOTO background

START /B upgrade\upgrade.bat B
GOTO end

:background
powershell -ExecutionPolicy ByPass -File upgrade\do_upgrade.ps1

:end
