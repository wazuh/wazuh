echo off

rem Searching for the IIS path
FOR %%F IN (%WinDir%\System32\LogFiles\W3SVC1 C:\) DO (
IF EXIST %%F echo %%F 
             echo lala
)

rem nc060215.log
