:: Simple script to restart ossec agent.
:: Copyright (C) 2015-2019, Wazuh Inc.
@ECHO OFF
ECHO.

:: Set some variables
FOR /F "TOKENS=1* DELIMS= " %%A IN ('DATE/T') DO SET DATE=%%A %%B
FOR /F "TOKENS=1-3 DELIMS=:" %%A IN ("%TIME%") DO SET TIME=%%A:%%B:%%C

:: Check for required arguments
IF "%1"=="add" GOTO ADD
IF "%1"=="delete" GOTO DEL

:ERROR
ECHO "Invalid argument. %1"
GOTO Exit;

:ADD
ECHO %DATE%%TIME% %0 %1 %2 %3 %4 %5 %6 %7 %8 %9 >> active-response/active-responses.log
net stop OssecSvc
net start OssecSvc
GOTO Exit;

:DEL
ECHO %DATE%%TIME% %0 %1 %2 %3 %4 %5 %6 %7 %8 %9 >> active-response/active-responses.log

:Exit
