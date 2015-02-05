REM Generate windows packages
REM Author: Michael Starks
REM Based on gen_win.sh by Daniel Cid

REM This program is a free software; you can redistribute it
REM and/or modify it under the terms of the GNU General Public
REM License (version 2) as published by the FSF - Free Software
REM Foundation

REM Enable delayed variable expansion
SETLOCAL ENABLEDELAYEDEXPANSION
SET FILE=win-files.txt
SET WINPKG=win-pkg

REM Check for public domain unix2dos.exe. It can be found here: http://www.efgh.com/software/unix2dos.htm
IF NOT EXIST unix2dos.exe echo unix2dos.exe not found, exiting... && EXIT 1

REM Generating configs
unix2dos.exe ossec.conf
type ossec.conf > ossec-win.conf
unix2dos.exe help.txt
type help.txt > help_win.txt
unix2dos.exe ..\..\etc\internal_options.conf
type ..\..\etc\internal_options.conf > internal_options-win.conf
unix2dos.exe ..\..\LICENSE
type ..\..\LICENSE > LICENSE.txt
unix2dos.exe ..\..\active-response\win\route-null.cmd
type ..\..\active-response\win\route-null.cmd > route-null.cmd
unix2dos.exe ..\..\active-response\win\restart-ossec.cmd
type ..\..\active-response\win\restart-ossec.cmd > restart-ossec.cmd

REM Going to the source dir
cd ..
IF NOT EXIST %WINPKG%\setup mkdir %WINPKG%\setup

FOR /F "tokens=1,2 delims= " %%i in (Win32\%FILE%) DO (
  REM Fix the slash
  SET FS1=%%i
  SET FS1=!FS1:/=\!
  SET FS2=%%j
  SET FS2=!FS2:/=\!
  IF EXIST !FS1!\NUL (
    xcopy "!FS1!" "%WINPKG%\!FS2!" /E /I /F /Y || echo Error copying !FS1! to "%WINPKG%\!FS2!" && EXIT 1
  ) ELSE (
  copy !FS1! "%WINPKG%\!FS2!" || echo Error copying !FS1! to "%WINPKG%\!FS2!" EXIT 1
  )
)

REM Final cleanup
del %WINPKG%\os_crypto\md5\main.c
del %WINPKG%\os_crypto\blowfish\main.c
del %WINPKG%\os_crypto\sha1\main.c
del %WINPKG%\os_crypto\md5_sha1\main.c
del %WINPKG%\shared\rules_op.c

ENDLOCAL
