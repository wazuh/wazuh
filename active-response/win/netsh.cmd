:: Simple script to block an ip using netsh. Commands from http://windowsnerd.com/
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
netsh ipsec static add policy description="ossec block list"
netsh ipsec static add filter filterlist="ossecfilter" srcaddr=%3 dstaddr=me protocol=tcp mirrored=yes
netsh ipsec static add rule policy="ossec" filterlist="ossecfilter" filteraction="block" desc="list of blocked ips"
netsh ipsec static set policy assign=y
GOTO Exit;

:DEL
netsh ipsec static delete filter filterlist="ossecfilter" srcaddr=%3 dstaddr=me protocol=tcp mirrored=yes

:Exit
