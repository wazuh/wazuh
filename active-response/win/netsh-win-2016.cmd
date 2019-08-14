:: Simple script to block an ip using netsh-advfirewall.
:: Copyright (C) 2015-2019, Wazuh Inc.
@ECHO OFF
ECHO.


:: Logging it all
FOR /F "TOKENS=1* DELIMS= " %%A IN ('DATE/T') DO SET DATE=%%B
FOR /F "TOKENS=1* DELIMS= " %%A IN ('TIME/T') DO SET TIME=%%A
ECHO %DATE% %TIME% %0 %1 %2 %3 %4 %5 %6 %7 %8 %9 >> active-response/active-responses.log


IF "%1"=="add" GOTO ADD
IF "%1"=="delete" GOTO DEL
:ERROR

ECHO "Invalid argument. %1"
GOTO Exit;


:: Adding to the blocked.

:ADD
:: Extracts last ip address from ipconfig.
netsh advfirewall firewall add rule name="WAZUH ACTIVE RESPONSE BLOCKED IP" interface=any dir=in action=block remoteip=%3/32
GOTO Exit;

:DEL
netsh advfirewall firewall delete rule name="WAZUH ACTIVE RESPONSE BLOCKED IP" remoteip=%3/32

:Exit
