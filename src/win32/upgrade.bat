@ECHO off

IF "%1"=="B" GOTO background

CD upgrade
TASKKILL /F /IM win32ui.exe > nul 2>&1
START /B upgrade.bat B
GOTO end

:background
DEL /Q upgrade_result 2> nul
SLEEP 5 2> NUL || ping -n 5 127.0.0.1 > NUL
FOR %%f IN (wazuh-agent-*.exe) DO (%%~nf /S)
ECHO 0 > upgrade_result

:end
