@ECHO off

IF "%1"=="B" GOTO background

CD upgrade
TASKKILL /F /IM win32ui.exe > nul 2>&1
START /B upgrade.bat B
GOTO end

:background
DEL /Q upgrade_result 2> nul
SLEEP 5
FOR /F "tokens=*" %G IN ('DIR /B wazuh-agent-*.exe') DO %G /S
NET START OssecSvc
ECHO 0 > upgrade_result

:end
