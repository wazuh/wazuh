:: Script to null route an ip address.
:: Copyright (C) 2015-2019, Wazuh Inc.
@ECHO OFF
ECHO.

:: Set some variables
FOR /F "TOKENS=1* DELIMS= " %%A IN ('DATE/T') DO SET DATE=%%A %%B
FOR /F "TOKENS=1-3 DELIMS=:" %%A IN ("%TIME%") DO SET TIME=%%A:%%B:%%C
SET IP_REGEX="[0-9][0-9]*[0-9]*\.[0-9][0-9]*[0-9]*\.[0-9][0-9]*[0-9]*\.[0-9][0-9]*[0-9]*"

:: Check for required arguments
IF /I "%1"=="" GOTO ERROR
IF /I "%1"=="add" GOTO ADD
IF /I "%1"=="delete" GOTO DEL

:ERROR
ECHO Invalid argument(s).
ECHO Usage: route-null.cmd ^(ADD^|DELETE^) - IPv4 Address
ECHO Example: route-null.cmd ADD - 1.2.3.4
ECHO Example: route-null.cmd DELETE - 1.2.3.4
EXIT /B 1

:ADD
:: Check for a valid IP
ECHO "%3" | %WINDIR%\system32\findstr.exe /R %IP_REGEX% >nul || ECHO Invalid IP && EXIT /B 2
:: Extracts last ip address from ipconfig and routes to this address. Windows will not allow routing to 127.0.0.1
FOR /F "TOKENS=2* DELIMS=:" %%A IN ('%WINDIR%\system32\ipconfig.exe ^| %WINDIR%\system32\findstr.exe /R /C:".*IP.*[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*"') DO FOR %%B IN (%%A) DO SET IPADDR=%%B
:: Adding IP to be null-routed. IP will be routed to local machine IP
%WINDIR%\system32\route.exe -p ADD %3 MASK 255.255.255.255 %IPADDR%
GOTO LOG

:DEL
:: Check for a valid IP
ECHO "%3" | %WINDIR%\system32\findstr.exe /R %IP_REGEX% >nul || ECHO Invalid IP && EXIT /B 2
:: Deleting IP
%WINDIR%\system32\route.exe DELETE %3
GOTO LOG

:LOG
ECHO %DATE%%TIME% %0 %1 %2 %3 %4 %5 %6 %7 %8 %9 >> active-response/active-responses.log
GOTO EXIT

:EXIT /B 0:
