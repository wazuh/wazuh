@echo off

rem Searching for IIS logs.
rem If we find any log in the NCSA format, change the config
rem to support that. If not, let the user know.
rem Example of log to look: nc060215.log

echo Looking for IIS log files to monitor.
echo For more information visit:
echo http://www.ossec.net/en/manual.html#iis

IF EXIST %WinDir%\System32\LogFiles\W3SVC1\nc??????.log (
    echo    * IIS NCSA log found. Changing config to read it.
    echo.  >> ossec.conf
    echo ^<ossec_config^> >> ossec.conf
    echo   ^<location^>%WinDir%\System32\LogFiles\W3SVC1\nc%%y%%m%%d.log^</location^> >> ossec.conf
    echo   ^<log_format^>iis^</log_format^> >> ossec.conf 
    echo ^</ossec_config^> >> ossec.conf >> ossec.conf
    pause
    exit )


IF EXIST %WinDir%\System32\LogFiles\W3SVC1 (
    echo    * IIS Log found. Look at the link above if you want to monitor it.
    pause
    exit )

rem EOF

