:: Script to null route an ip address.
@ECHO OFF
ECHO.

:: Set some variables
FOR /F "TOKENS=1* DELIMS= " %%A IN ('DATE/T') DO SET DAT=%%A %%B
FOR /F "TOKENS=1-3 DELIMS=:" %%A IN ("%TIME%") DO SET TIM=%%A:%%B:%%C

:: Check for required arguments
IF /I "%1"=="" GOTO ERROR
IF /I "%2"=="" GOTO ERROR

:: Check for a valid IP
ECHO "%2" | %WINDIR%\system32\findstr.exe /R "\." >nul || GOTO ipv6

set prefixlength=32
set gateway=0.0.0.0
goto x

:ipv6
set prefixlength=128
set gateway=::

:x

IF /I "%1"=="add" GOTO ADD
IF /I "%1"=="delete" GOTO DEL

:ERROR
ECHO Invalid argument(s).
ECHO Usage: route-null.cmd ^(ADD^|DELETE^) IP Address
ECHO Example: route-null.cmd ADD 1.2.3.4
EXIT /B 1

:: Adding IP to be null-routed.

:ADD
%WINDIR%\system32\route.exe ADD %2/%prefixlength% %gateway%
:: Log it
ECHO %DAT%%TIM% %~dp0%0 %1 - %2 >> "%OSSECPATH%active-response\active-responses.log"
GOTO EXIT

:DEL
%WINDIR%\system32\route.exe DELETE %2/%prefixlength%
ECHO %DAT%%TIM% %~dp0%0 %1 - %2 >> "%OSSECPATH%active-response\active-responses.log"

:EXIT /B 0:
