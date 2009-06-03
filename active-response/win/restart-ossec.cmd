:: Simple script to restart ossec agent.
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


:ADD
net stop OssecSvc
net start OssecSvc

GOTO Exit;

:DEL

:Exit
