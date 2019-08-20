@ECHO OFF
::
:: Wrapper for invoking CIS-CAT
::

SET DEBUG=0

SET JAVA=java

::
:: Detect if Java is in the path
::

%JAVA% 2> NUL > NUL

IF NOT %ERRORLEVEL%==9009 IF NOT %ERRORLEVEL%==3 GOTO RUNCISCAT

::
:: If Java is not in the PATH, try finding it at JAVA_HOME\bin
::

SET JAVA=%JAVA_HOME%\bin\java.exe

%JAVA% 2> NUL > NUL

IF NOT %ERRORLEVEL%==9009 IF NOT %ERRORLEVEL%==3 GOTO RUNCISCAT

::
:: See if x86 JRE5 is in the default location
::

SET JAVA=C:\PROGRA~2\Java\jre5\bin\java.exe

%JAVA% 2> NUL > NUL

IF NOT %ERRORLEVEL%==9009 IF NOT %ERRORLEVEL%==3 GOTO RUNCISCAT

::
:: See if x86 JRE6 is in the default location
::

SET JAVA=C:\PROGRA~2\Java\jre6\bin\java.exe

%JAVA% 2> NUL > NUL

IF NOT %ERRORLEVEL%==9009 IF NOT %ERRORLEVEL%==3 GOTO RUNCISCAT

::
:: See if x86 JRE7 is in the default location
::

SET JAVA=C:\PROGRA~2\Java\jre7\bin\java.exe

%JAVA% 2> NUL > NUL

IF NOT %ERRORLEVEL%==9009 IF NOT %ERRORLEVEL%==3 GOTO RUNCISCAT

::
:: See if x86 JRE8 is in the default location
::

SET JAVA=C:\PROGRA~2\Java\jre8\bin\java.exe

%JAVA% 2> NUL > NUL

IF NOT %ERRORLEVEL%==9009 IF NOT %ERRORLEVEL%==3 GOTO RUNCISCAT

::
:: See if JRE6 is in the default location
::

SET JAVA=C:\PROGRA~1\Java\jre6\bin\java.exe

%JAVA% 2> NUL > NUL

IF NOT %ERRORLEVEL%==9009 IF NOT %ERRORLEVEL%==3 GOTO RUNCISCAT

::
:: See if JRE7 is in the default location
::

SET JAVA=C:\PROGRA~1\Java\jre7\bin\java.exe

%JAVA% 2> NUL > NUL

IF NOT %ERRORLEVEL%==9009 IF NOT %ERRORLEVEL%==3 GOTO RUNCISCAT

::
:: See if JRE8 is in the default location
::

SET JAVA=C:\PROGRA~1\Java\jre8\bin\java.exe

%JAVA% 2> NUL > NUL

IF NOT %ERRORLEVEL%==9009 IF NOT %ERRORLEVEL%==3 GOTO RUNCISCAT

IF %ERRORLEVEL%==9009 GOTO NOJAVAERROR
IF %ERRORLEVEL%==3 GOTO NOJAVAERROR

::
:: Invoke CIS-CAT with a 768MB heap
::

:RUNCISCAT

IF %DEBUG%==1 (
	ECHO Found Java at %JAVA%
	ECHO Running CIS-CAT from "%~dp0"
	%JAVA% -Xmx768M -jar "%~dp0\CISCAT.jar" %* --verbose
) ELSE (
	%JAVA% -Xmx768M -jar "%~dp0\CISCAT.jar" %*
)

GOTO EXIT

:NOJAVAERROR

ECHO The Java runtime was not found in PATH, default install locations, or JAVA_HOME.  Please ensure Java is installed.
PAUSE

:EXIT


