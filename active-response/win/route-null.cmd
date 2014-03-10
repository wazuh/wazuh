:: Script to null route an ip address.
@ECHO OFF
ECHO.

:: Set some variables
FOR /F "TOKENS=1* DELIMS= " %%A IN ('DATE/T') DO SET DAT=%%A %%B
FOR /F "TOKENS=1-3 DELIMS=:" %%A IN ("%TIME%") DO SET TIM=%%A:%%B:%%C

:: Check for required arguments
IF /I "%1"=="" GOTO ERROR
IF /I "%1"=="add" GOTO ADD
IF /I "%1"=="delete" GOTO DEL

:ERROR
ECHO Invalid argument(s).
ECHO Usage: route-null.cmd ^(ADD^|DELETE^) IPv4 Address 
ECHO Example: route-null.cmd ADD 1.2.3.4
EXIT /B 1


:: Adding IP to be null-routed. IP will be routed to local machine IP

:ADD
:: Check for a valid IP
ECHO "%2" | %WINDIR%\system32\findstr.exe /R "[0-2][0-9]*[0-9]*\.[0-2][0-9]*[0-9]*\.[0-2][0-9]*[0-9]*\.[0-2][0-9]*[0-9]*" >nul || ECHO Invalid IP && EXIT /B 2 
:: Extracts last ip address from ipconfig and routes to this address. Windows will not allow routing to 127.0.0.1
FOR /F "TOKENS=2* DELIMS=:" %%A IN ('%WINDIR%\system32\ipconfig.exe ^| %WINDIR%\system32\findstr.exe /R /C:"IPv*4* Address"') DO FOR %%B IN (%%A) DO SET IPADDR=%%B
%WINDIR%\system32\route.exe ADD %2 MASK 255.255.255.255 %IPADDR%
:: Log it
ECHO %DAT%%TIM% %~dp0%0 %1 - %2 >> "%OSSECPATH%active-response\active-responses.log"
GOTO EXIT

:DEL
ECHO "%2" | %WINDIR%\system32\findstr.exe /R "[0-2][0-9]*[0-9]*\.[0-2][0-9]*[0-9]*\.[0-2][0-9]*[0-9]*\.[0-2][0-9]*[0-9]*" >nul || ECHO Invalid IP && EXIT /B 2
%WINDIR%\system32\route.exe DELETE %2
ECHO %DAT%%TIM% %~dp0%0 %1 - %2 >> "%OSSECPATH%active-response\active-responses.log"

:EXIT /B 0:
