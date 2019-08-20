@ECHO OFF

::
:: Centralized CIS-CAT Wrapper v2.0.7
::
:: This batch file assists in executing CIS-CAT on a population of Microsoft
:: Windows targets from a centralized location. Please review the CIS-CAT 
:: User Guide for detailed instructions on how to leverage this file. 
::
:: Acknowledgements:
:: 
::    Michael Morton introduced the concept of invoking CIS-CAT via a 
::    centralized batch file and provided the original batch file.
::
::    Gary King of Atlas Pipeline introduced the concept of including 
::    detection logic to determine which benchmark and profile to execute.
::
:: Please send questions/comments/improvements to feedback@cisecurity.org.
::

::
:: Toggle Debugging Information
::

SET DEBUG=0

::
:: Toggle Timed CIS-CAT Version
:: When using this script with a timed/trial version of CIS-CAT, 
:: the value of TIMED _MUST_ be 1.
::

SET TIMED=0

::
:: Setting AUTODETECT=1 will cause this script to detect the following:
::             - Which CIS Windows Benchmark to run
::             - Which Benchmark Profile to select
::             - Which JRE to leverage (32- or 64-bit). Defaults to 32-bit
::

SET AUTODETECT=1

::
:: Setting SSLF=1 will cause CIS-CAT to execute the SSLF (high security) 
:: profile in place of the Enterprise Profile.
::
:: 	Note: This variable is only significant when AUTODETECT=1
::

SET SSLF=0

::
:: UNC path to the network share where the base CIS assessment bundle resides
::

SET NetworkShare=.

::
:: Path to debug log when DEBUG=1
::

SET DebugLogFile=%NetworkShare%\cis-cat-debug-log.txt

::
:: The path to the 32-bit JRE, relative to the path set in NetworkShare
:: Use http://www.java.com/en/download/manual.jsp (Windows Offline (32-bit)
:: 		Direct: http://javadl.sun.com/webapps/download/AutoDL?BundleId=61043 
::

SET JavaPath=Java\jre

::
:: The path to the 64-bit JRE, relative to the path set in NetworkShare
::

SET JavaPath64=Java\jre

::
:: Configure the maximum heap size to be allocated by the JRE, in Megabytes
::

SET JavaMaxMemoryMB=768

::
:: The path to the CIS-CAT archive, relative to the path set in NetworkShare
::

SET CisCatPath=cis-cat-full
IF %TIMED%==1 SET CisCatPath=cis-cat-timed14
::
:: The path to location where CIS-CAT reports should be placed, relative to 
:: the path set in NetworkShare
::

SET ReportsPath=Reports

::
:: Configure CIS-CAT report generation options:
::
::	-x   : Generate an XML report
::	-t   : Generate a Text report
::	-csv : Generate a CSV report
::	-y   : Causes the HTML and Text reports to display all tests (default is only applicable tests)
::	-n   : Do NOT generate an HTML report
::

SET CISCAT_OPTS=-x -t -csv

::
:: The file name of the CIS Benchmark to run. It is assumed this file resides
:: under CisCatPath\benchmarks\.
::
:: 	Note: This value will be overridden if AUTODETECT=1.
:: 	Note: This value will be overridden if a benchmark is specified via the
:: 	      command line. 
::

SET Benchmark=CIS_Microsoft_Windows_Server_2003_Benchmark_v3.1.0-xccdf.xml

::
:: The Benchmark Profile to execute. A list of profiles, delimited by a 
:: space (" ") can be provided to evaluate multiple profiles.
::
:: 	Note: This value will be overridden if AUTODETECT=1.
:: 	Note: This value will be overridden if a benchmark is specified via 
:: 	      the command line.
::

SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::                                                                           ::  
:: No need to change anything below here                                     ::
::                                                                           ::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

ECHO.
ECHO Centralized CIS-CAT Wrapper v2.0.7

SET ARCH=UNKNOWN
SET OS=UNKNOWN
SET DOMAINROLE=UNKNOWN

IF %AUTODETECT%==0 GOTO NODETECTOS

::
:: Detect Windows OS Version
::

ECHO.
ECHO Detecting OS...

WMIC OS GET "Name" | FINDSTR /C:" 7" > NUL
IF %ERRORLEVEL%==0 SET OS=WIN7
IF %ERRORLEVEL%==0 GOTO FOUNDOS

WMIC OS GET "Name" | FINDSTR /C:" XP" > NUL
IF %ERRORLEVEL% == 0 SET OS=WINXP
IF %ERRORLEVEL% == 0 GOTO FOUNDOS

WMIC OS GET "Name" | FINDSTR /C:" 2003" > NUL
IF %ERRORLEVEL% == 0 SET OS=WIN2003
IF %ERRORLEVEL% == 0 GOTO FOUNDOS

WMIC OS GET "Name" | FINDSTR /C:" 2008 R2" > NUL
IF %ERRORLEVEL% == 0 SET OS=WIN2008R2
IF %ERRORLEVEL% == 0 GOTO FOUNDOS

WMIC OS GET "Name" | FINDSTR /C:" 2008" > NUL
IF %ERRORLEVEL% == 0 SET OS=WIN2008
IF %ERRORLEVEL% == 0 GOTO FOUNDOS

WMIC OS GET "Name" | FINDSTR /C:" 8.1" > NUL
IF %ERRORLEVEL%==0 SET OS=WIN81
IF %ERRORLEVEL%==0 GOTO FOUNDOS

WMIC OS GET "Name" | FINDSTR /C:" 8" > NUL
IF %ERRORLEVEL%==0 SET OS=WIN8
IF %ERRORLEVEL%==0 GOTO FOUNDOS

WMIC OS GET "Name" | FINDSTR /C:" 10" > NUL
IF %ERRORLEVEL%==0 SET OS=WIN10
IF %ERRORLEVEL%==0 GOTO FOUNDOS

WMIC OS GET "Name" | FINDSTR /C:" 2012 R2" > NUL
IF %ERRORLEVEL% == 0 SET OS=WIN2012R2
IF %ERRORLEVEL% == 0 GOTO FOUNDOS

WMIC OS GET "Name" | FINDSTR /C:" 2012" > NUL
IF %ERRORLEVEL% == 0 SET OS=WIN2012
IF %ERRORLEVEL% == 0 GOTO FOUNDOS

WMIC OS GET "Name" | FINDSTR /C:" 2016" > NUL
IF %ERRORLEVEL% == 0 SET OS=WIN2016
IF %ERRORLEVEL% == 0 GOTO FOUNDOS

ECHO "Critical Error: Unable to Detect OS."
GOTO EXIT

:FOUNDOS

ECHO Found OS %OS%.

:NODETECTOS

IF %AUTODETECT%==0 GOTO NODETECTARCH 

::
:: Detect Architecture
::

ECHO.
ECHO Detecting Architecture...

:: The %ProgramW6432% environment variable is only set on 64-bit systems. 
:: It will be expanded to a value other than NULL if it is set.

ECHO %ProgramW6432% | FINDSTR /C:"Program Files"

IF %ERRORLEVEL% == 0 SET ARCH=64
IF %ERRORLEVEL% == 1 SET ARCH=32

ECHO Found %ARCH% bit Architecture. 

:NODETECTARCH

IF %AUTODETECT%==0 GOTO NODETECTROLE

::
:: Detect Domain Role
::

ECHO.
ECHO Detecting Domain Role...

:: http://msdn.microsoft.com/en-us/library/aa394102%28v=vs.85%29.aspx

WMIC COMPUTERSYSTEM GET "DomainRole" | FINDSTR 0 > NUL
IF %ERRORLEVEL% == 0 SET DOMAINROLE=WORKSTATION_STANDALONE
IF %ERRORLEVEL% == 0 GOTO FOUNDROLE

WMIC COMPUTERSYSTEM GET "DomainRole" | FINDSTR 1 > NUL
IF %ERRORLEVEL% == 0 SET DOMAINROLE=WORKSTATION_DOMAIN_JOINED
IF %ERRORLEVEL% == 0 GOTO FOUNDROLE

WMIC COMPUTERSYSTEM GET "DomainRole" | FINDSTR 2 > NUL
IF %ERRORLEVEL% == 0 SET DOMAINROLE=SERVER_STANDALONE
IF %ERRORLEVEL% == 0 GOTO FOUNDROLE

WMIC COMPUTERSYSTEM GET "DomainRole" | FINDSTR 3 > NUL
IF %ERRORLEVEL% == 0 SET DOMAINROLE=SERVER_DOMAIN_JOINED
IF %ERRORLEVEL% == 0 GOTO FOUNDROLE

WMIC COMPUTERSYSTEM GET "DomainRole" | FINDSTR 4 > NUL
IF %ERRORLEVEL% == 0 SET DOMAINROLE=SERVER_DOMAIN_CONTROLLER
IF %ERRORLEVEL% == 0 GOTO FOUNDROLE

WMIC COMPUTERSYSTEM GET "DomainRole" | FINDSTR 5 > NUL
IF %ERRORLEVEL% == 0 SET DOMAINROLE=SERVER_DOMAIN_CONTROLLER
IF %ERRORLEVEL% == 0 GOTO FOUNDROLE

ECHO "Critical Error: Unable to Detect Domain Role."
GOTO EXIT

:FOUNDROLE

ECHO Found Role %DOMAINROLE%

:NODETECTROLE

::
:: Test if Benchmark and Profile are provided via command line. If so, disable 
:: AUTODETECT and use those values instead of the values hardcoded above.
::

IF %1.==. GOTO NOARG
IF %2.==. GOTO NOARG

SET AUTODETECT=0

SET Benchmark=%1
SET Profiles=%2

:NOARG

ECHO.
ECHO Setting up Environment...

PUSHD .

PUSHD %NetworkShare% > nul 2> nul

IF NOT %ERRORLEVEL% == 0 GOTO ERRORDRIVE
SET MapDrive=%cd%

SET mJavaPath=%MapDrive%\%JavaPath%
SET mCisCatPath=%MapDrive%\%CisCatPath%
SET mReportsPath=%MapDrive%\%ReportsPath%
SET JAVA_HOME=%MapDrive%\%JavaPath%

::
:: Fixup JAVA_HOME and Java Location based on ARCH if AUTODETECT is enabled.
::

IF %AUTODETECT%==0 GOTO NOJAVAFIXUP
IF %ARCH%==64 SET JAVA_HOME=%MapDrive%\%JavaPath64%
IF %ARCH%==64 SET mJavaPath=%MapDrive%\%JavaPath64%

:NOJAVAFIXUP

IF %DEBUG%==1 ECHO %mJavaPath% points to %NetworkShare%\%JavaPath%
IF %DEBUG%==1 ECHO %mCisCatPath% points to %NetworkShare%\%CisCatPath%
IF %DEBUG%==1 ECHO %mReportsPath% points to %NetworkShare%\%ReportsPath%
IF %DEBUG%==1 ECHO %JAVA_HOME% points to %NetworkShare%\%JavaPath% 

cd %mCisCatPath%

IF NOT EXIST %mJavaPath% GOTO ERROR_JAVA_PATH
IF NOT EXIST %mJavaPath%\bin\java.exe GOTO ERROR_JAVAEXE_PATH
IF NOT EXIST %mCisCatPath% GOTO ERROR_CISCAT_PATH
IF NOT EXIST %mCisCatPath%\CISCAT.jar GOTO ERROR_CISCATJAR_PATH
IF NOT EXIST %mReportsPath% GOTO ERROR_REPORTS_PATH

IF %TIMED%==1 GOTO TIMEDNOBENCHMARKPATH 
IF NOT EXIST benchmarks/%Benchmark% GOTO ERROR_BENCHMARK_PATH

:TIMEDNOBENCHMARKPATH

ECHO.
ECHO	Local Drive: 	%MapDrive%
ECHO	  JAVA_HOME:	%NetworkShare%\%JavaPath%
ECHO	    CIS-CAT:	%NetworkShare%\%CisCatPath%
ECHO	    Reports:	%NetworkShare%\%ReportsPath%
ECHO.

::
:: Select the correct benchmark based on AUTODETECT 
::

IF %AUTODETECT%==0 GOTO NOBENCHMARKFIXUP

::
:: Test for WINXP
::

IF NOT %OS%==WINXP GOTO NOTXP

SET Benchmark=CIS_Microsoft_Windows_XP_Benchmark_v3.1.0-xccdf.xml

:: [1]  xccdf_org.cisecurity.benchmarks_profile_Level_1

IF %SSLF%==1 GOTO XPSSLF

IF %DOMAINROLE%==WORKSTATION_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1
IF %DOMAINROLE%==WORKSTATION_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1

GOTO NOBENCHMARKFIXUP

:XPSSLF

IF %DOMAINROLE%==WORKSTATION_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1
IF %DOMAINROLE%==WORKSTATION_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1

GOTO NOBENCHMARKFIXUP

:NOTXP

::
:: Test for WIN7
::

IF NOT %OS%==WIN7 GOTO NOTWIN7

SET Benchmark=CIS_Microsoft_Windows_7_Benchmark_v3.0.1-xccdf.xml

:: [1]  xccdf_org.cisecurity.benchmarks_profile_Level_1
:: [2]  xccdf_org.cisecurity.benchmarks_profile_Level_1__BitLocker
:: [3]  xccdf_org.cisecurity.benchmarks_profile_Level_2
:: [4]  xccdf_org.cisecurity.benchmarks_profile_Level_2__BitLocker

IF %SSLF%==1 GOTO WIN7SSLF

IF %DOMAINROLE%==WORKSTATION_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1
IF %DOMAINROLE%==WORKSTATION_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1

GOTO NOBENCHMARKFIXUP

:WIN7SSLF

IF %DOMAINROLE%==WORKSTATION_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2
IF %DOMAINROLE%==WORKSTATION_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2

GOTO NOBENCHMARKFIXUP

:NOTWIN7

::
:: Test for WIN8
::

IF NOT %OS%==WIN8 GOTO NOTWIN8

SET Benchmark=CIS_Microsoft_Windows_8_Benchmark_v1.0.0-xccdf.xml

:: [1]  xccdf_org.cisecurity.benchmarks_profile_Level_1
:: [2]  xccdf_org.cisecurity.benchmarks_profile_Level_1__BitLocker

IF %SSLF%==1 GOTO WIN8SSLF

IF %DOMAINROLE%==WORKSTATION_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1
IF %DOMAINROLE%==WORKSTATION_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1

GOTO NOBENCHMARKFIXUP

:WIN8SSLF

IF %DOMAINROLE%==WORKSTATION_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1__BitLocker
IF %DOMAINROLE%==WORKSTATION_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1__BitLocker

GOTO NOBENCHMARKFIXUP

:NOTWIN8

::
:: Test for WIN 8.1
::

IF NOT %OS%==WIN81 GOTO NOTWIN81

SET Benchmark=CIS_Microsoft_Windows_8.1_Workstation_Benchmark_v2.2.1-xccdf.xml

:: [1]  xccdf_org.cisecurity.benchmarks_profile_Level_1
:: [2]  xccdf_org.cisecurity.benchmarks_profile_Level_1__BitLocker
:: There are also:
::   - xccdf_org.cisecurity.benchmarks_profile_Level_1__BitLocker
::   - xccdf_org.cisecurity.benchmarks_profile_Level_2__BitLocker

IF %SSLF%==1 GOTO WIN81SSLF

IF %DOMAINROLE%==WORKSTATION_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1
IF %DOMAINROLE%==WORKSTATION_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1

GOTO NOBENCHMARKFIXUP

:WIN81SSLF

IF %DOMAINROLE%==WORKSTATION_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2
IF %DOMAINROLE%==WORKSTATION_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2

GOTO NOBENCHMARKFIXUP

:NOTWIN81

::
:: Test for WIN 10
::

IF NOT %OS%==WIN10 GOTO NOTWIN10

SET Benchmark=CIS_Microsoft_Windows_10_Enterprise_Release_1607_Benchmark_v1.2.0-xccdf.xml

:: [1]  xccdf_org.cisecurity.benchmarks_profile_Level_1
:: [2]  xccdf_org.cisecurity.benchmarks_profile_Level_2
:: There are also:
::   - xccdf_org.cisecurity.benchmarks_profile_Level_1__BitLocker
::   - xccdf_org.cisecurity.benchmarks_profile_Level_2__BitLocker

IF %SSLF%==1 GOTO WIN10SSLF

IF %DOMAINROLE%==WORKSTATION_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1
IF %DOMAINROLE%==WORKSTATION_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1

GOTO NOBENCHMARKFIXUP

:WIN10SSLF

IF %DOMAINROLE%==WORKSTATION_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2
IF %DOMAINROLE%==WORKSTATION_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2

GOTO NOBENCHMARKFIXUP

:NOTWIN10

::
:: Test for WIN2003
::

IF NOT %OS%==WIN2003 GOTO NOT2003

SET Benchmark=CIS_Microsoft_Windows_Server_2003_Benchmark_v3.1.0-xccdf.xml

:: [1]  xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller
:: [2]  xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server

IF %SSLF%==1 GOTO SSLF2003

IF %DOMAINROLE%==SERVER_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_CONTROLLER SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller

GOTO NOBENCHMARKFIXUP

:SSLF2003

IF %DOMAINROLE%==SERVER_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_CONTROLLER SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller

GOTO NOBENCHMARKFIXUP

:NOT2003

::
:: Test for WIN2008R2
::

IF NOT %OS%==WIN2008R2 GOTO NOT2008R2

SET Benchmark=CIS_Microsoft_Windows_Server_2008_R2_Benchmark_v3.0.1-xccdf.xml

:: [1]  xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller
:: [2]  xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
:: [3]  xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Domain_Controller
:: [4]  xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server

IF %SSLF%==1 GOTO SSLF2008R2

IF %DOMAINROLE%==SERVER_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_CONTROLLER SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller

GOTO NOBENCHMARKFIXUP

:SSLF2008R2

IF %DOMAINROLE%==SERVER_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_CONTROLLER SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Domain_Controller

GOTO NOBENCHMARKFIXUP

:NOT2008R2

::
:: Test for WIN2008
::

IF NOT %OS%==WIN2008 GOTO NOT2008

SET Benchmark=CIS_Microsoft_Windows_Server_2008_Benchmark_v3.0.0-xccdf.xml

:: [1]  xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller
:: [2]  xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
:: [3]  xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Domain_Controller
:: [4]  xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server

IF %SSLF%==1 GOTO SSLF2008

IF %DOMAINROLE%==SERVER_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_CONTROLLER SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller

GOTO NOBENCHMARKFIXUP

:SSLF2008

IF %DOMAINROLE%==SERVER_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_CONTROLLER SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Domain_Controller

GOTO NOBENCHMARKFIXUP


:NOT2008

::
:: Test for WIN2012R2
::

IF NOT %OS%==WIN2012R2 GOTO NOT2012R2

SET Benchmark=CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v2.2.1-xccdf.xml

:: [1]  xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller
:: [2]  xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
:: [3]  xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Domain_Controller
:: [4]  xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server

IF %SSLF%==1 GOTO SSLF2012R2

IF %DOMAINROLE%==SERVER_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_CONTROLLER SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller

GOTO NOBENCHMARKFIXUP

:SSLF2012R2

IF %DOMAINROLE%==SERVER_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_CONTROLLER SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Domain_Controller

GOTO NOBENCHMARKFIXUP

:NOT2012R2

::
:: Test for WIN2012
::

IF NOT %OS%==WIN2012 GOTO NOT2012

SET Benchmark=CIS_Microsoft_Windows_Server_2012_non-R2_Benchmark_v2.0.1-xccdf.xml

:: [1]  xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller
:: [2]  xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
:: [3]  xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Domain_Controller
:: [4]  xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server

IF %SSLF%==1 GOTO SSLF2012

IF %DOMAINROLE%==SERVER_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_CONTROLLER SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller

GOTO NOBENCHMARKFIXUP

:SSLF2012

IF %DOMAINROLE%==SERVER_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_CONTROLLER SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Domain_Controller

GOTO NOBENCHMARKFIXUP

:NOT2012

::
:: Test for WIN2016
::

IF NOT %OS%==WIN2016 GOTO NOT2016

SET Benchmark=CIS_Microsoft_Windows_Server_2016_Benchmark_v1.0.0-xccdf.xml

:: [1]  xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller
:: [2]  xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
:: [3]  xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Domain_Controller
:: [4]  xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server

IF %SSLF%==1 GOTO SSLF2016

IF %DOMAINROLE%==SERVER_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_CONTROLLER SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Domain_Controller

GOTO NOBENCHMARKFIXUP

:SSLF2016

IF %DOMAINROLE%==SERVER_STANDALONE SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_JOINED SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server
IF %DOMAINROLE%==SERVER_DOMAIN_CONTROLLER SET Profiles=xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Domain_Controller

GOTO NOBENCHMARKFIXUP

:NOT2016

:NOBENCHMARKFIXUP

IF %DEBUG%==1 ECHO Start: Computer = %COMPUTERNAME% >> %DebugLogFile%
IF %DEBUG%==1 ECHO mJavaPath = %mJavaPath% >> %DebugLogFile%
IF %DEBUG%==1 ECHO mCisCatPath = %mCisCatPath% >> %DebugLogFile%
IF %DEBUG%==1 ECHO mReportsPath = %mReportsPath% >>  %DebugLogFile%
IF %DEBUG%==1 ECHO JAVA_HOME = %JAVA_HOME% >> %DebugLogFile%
IF %DEBUG%==1 ECHO Benchmark = %Benchmark% >> %DebugLogFile%
IF %DEBUG%==1 ECHO ARCH = %ARCH% >> %DebugLogFile%
IF %DEBUG%==1 ECHO OS = %OS% >> %DebugLogFile%
IF %DEBUG%==1 ECHO DOMAINROLE = %DOMAINROLE% >> %DebugLogFile%

::
:: Put all the options together and form the CIS-CAT command-line
::
:: When using the timed version of CIS-CAT, the benchmarks are stored in the jar, 
:: so the path to the benchmark needs to indicate the resource path, for example
:: /benchmarks/%Benchmark%
:: SET FULL_CISCAT_CMD=%mJavaPath%\bin\java.exe -Xmx%JavaMaxMemoryMB%M -jar %mCisCatPath%\CISCAT.jar -a -s %CISCAT_OPTS% -b /benchmarks/%Benchmark%
::
IF %TIMED%==1 (
	SET FULL_CISCAT_CMD=%mJavaPath%\bin\java.exe -Xmx%JavaMaxMemoryMB%M -jar %mCisCatPath%\CISCAT.jar -a -s %CISCAT_OPTS% -b /benchmarks/%Benchmark% 
) ELSE (
	SET FULL_CISCAT_CMD=%mJavaPath%\bin\java.exe -Xmx%JavaMaxMemoryMB%M -jar %mCisCatPath%\CISCAT.jar -a -s %CISCAT_OPTS% -b %mCisCatPath%\benchmarks\%Benchmark%
)

ECHO	  Benchmark:	%Benchmark%
ECHO	 Profile(s):	%Profiles%
ECHO.
ECHO Starting Assessment(s)...
FOR %%P IN (%Profiles%) DO (
	ECHO  + %FULL_CISCAT_CMD% -p "%%P" -r "%mReportsPath%"
	ECHO  + Running Profile %%P...
	ECHO.
	ECHO [[ CIS-CAT ASSESSMENT START ]]
	IF %DEBUG%==1 ECHO CMDLINE = %FULL_CISCAT_CMD% -p "%%P" -r "%mReportsPath%" >> %DebugLogFile%
	%FULL_CISCAT_CMD% -p "%%P" -r "%mReportsPath%" 
	ECHO [[  CIS-CAT OUTPUT END  ]]
	ECHO.
)

ECHO Testing Complete. 
ECHO Reports can be found at %NetworkShare%\%ReportsPath%

GOTO EXIT

:ERRORDRIVE
ECHO Critical Error: Unable to Map %NetworkShare%. 
ECHO Ensure the directory exists and has the appropriate permissions set.
IF %DEBUG%==1 ECHO ERRORDRIVE >> %DebugLogFile%
GOTO EXIT

:ERROR_JAVA_PATH
ECHO Critical Error: The directory %NetworkShare%\%JavaPath% does not exist.
ECHO Ensure the JavaPath and JavaPath64 variables are set correctly. 
IF %DEBUG%==1 ECHO ERROR_JAVA_PATH >> %DebugLogFile%
GOTO EXIT

:ERROR_JAVAEXE_PATH
ECHO Critical Error: java.exe can not be found at %NetworkShare%\%JavaPath%\bin\.
ECHO Ensure the JavaPath and JavaPath64 variables are set correctly. 
IF %DEBUG%==1 ECHO ERROR_JAVAEXE_PATH >> %DebugLogFile%
GOTO EXIT

:ERROR_CISCAT_PATH
ECHO Critical Error: The directory %NetworkShare%\%CisCatPath% does not exist.
ECHO Ensure the CisCatPath variable is set correctly.
IF %DEBUG%==1 ECHO ERROR_CISCAT_PATH >> %DebugLogFile%
GOTO EXIT

:ERROR_REPORTS_PATH
ECHO Critical Error: The directory %NetworkShare%\%ReportsPath% does not exist.
ECHO Ensure the ReportsPath variable is set correctly.  
IF %DEBUG%==1 ECHO ERROR_REPORTS_PATH >> %DebugLogFile%
GOTO EXIT

:ERROR_BENCHMARK_PATH
ECHO Critical Error: Benchmark %NetworkShare%\%CisCatPath%\benchmarks\%Benchmark% does not exist. 
ECHO Ensure the Benchmark is set correctly. 
ECHO Ensure the command line arguments passed to this script are accurate.
IF %DEBUG%==1 ECHO ERROR_BENCHMARK_PATH >> %DebugLogFile%
GOTO EXIT

:ERROR_CISCATJAR_PATH
ECHO Critical Error: CISCAT.jar does not exist at %NetworkShare%\%CisCatPath%\. 
ECHO Ensure the CisCatPath variable is set correctly. 
IF %DEBUG%==1 ECHO ERROR_CISCATJAR_PATH >> %DebugLogFile%
GOTO EXIT

:EXIT
IF %DEBUG%==1 ECHO Stop: Computer = %COMPUTERNAME% >> %DebugLogFile%
POPD


