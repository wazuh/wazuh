@ECHO OFF
REM 
REM cis-cat-jump.bat
REM
REM This batch file is designed to assist in leveraging CIS-CAT from writable removable media,
REM such as jump drive. 
REM 
REM The following details the various variables you are expected to set when deploying this script
REM along with the actions this script will take.
REM
REM The %BasePath% variables must point to your jump drive.
REM 
REM The %Benchmark% variable specifies the benchmark to evaluate.
REM
REM The %CisCatPath% variable must point to the parent folder of CISCAT.jar.
REM
REM The %JavaPath% variable must point to the Java Runtime Environment.
REM 
REM The %ReportsPath% variable specifies the location where CIS-CAT will write evaluation reports.
REM
REM The %Profiles% variable accepts a space (" ") delimited list of profiles to be evaluated.
REM See \\HostingServer\CIS-CAT\cis-cat\benchmarks\ for a list of available options.
REM
REM As currently set, this batch file assumes the following directory structure exists on the removable media:
REM
REM	L:\CIS
REM	L:\CIS\CIS-CAT\CISCAT.jar
REM	L:\CIS\CIS-CAT\py
REM	L:\CIS\CIS-CAT\lib
REM	L:\CIS\CIS-CAT\benchmarks
REM	L:\CIS\Java\jre_1.5.0_19\bin\
REM	L:\CIS\Java\jre_1.5.0_19\lib\
REM	L:\CIS\Reports
REM
REM These are the only variables that need to be modified:

SET BasePath=L:\CIS
SET JavaPath=%BasePath%\Java\jre1.5.0_19
SET CisCatPath=%BasePath%\CIS-CAT
SET ReportsPath=%BasePath%\Reports
SET Benchmark=CIS_Microsoft_Windows_2003_MS_DC_Benchmark_v2.0.0.xml
SET Profiles="ms-legacy"  "dc-legacy"

REM Do not modify anything under here.

ECHO JavaPath points to %JavaPath%
ECHO CisCatPath points to %CisCatPath%
ECHO ReportsPath points to %ReportsPath%
ECHO JAVA_HOME points to %JAVA_HOME%

pushd .

cd %CisCatPath%

IF NOT EXIST %JavaPath% GOTO ERROR_JAVA_PATH
IF NOT EXIST %JavaPath%\bin\java.exe GOTO ERROR_JAVAEXE_PATH
IF NOT EXIST %CisCatPath% GOTO ERROR_CISCAT_PATH
IF NOT EXIST %CisCatPath%\CISCAT.jar GOTO ERROR_CISCATJAR_PATH
IF NOT EXIST %ReportsPath% GOTO ERROR_REPORTS_PATH
IF NOT EXIST benchmarks/%Benchmark% GOTO ERROR_BENCHMARK_PATH

FOR %%P IN (%Profiles%) DO (
echo Evaluating Benchmark %Benchmark%, profile %%P
%JavaPath%\bin\java.exe -Xmx768M -jar CISCAT.jar -a -s -b benchmarks/%Benchmark% -p "%%P" -r "%ReportsPath%" 
)

echo Testing Complete. 
echo Results can be found at %ReportsPath%

GOTO EXIT

:ERROR_JAVA_PATH
ECHO Critical Error: The JavaPath variable does not appear to be set correctly. The directory %JavaPath% does not exist.
GOTO EXIT

:ERROR_JAVAEXE_PATH
ECHO Critical Error: The java.exe executable can not be found at %JavaPath%\bin\java.exe. Ensure can JavaPath variable is set correctly.
GOTO EXIT

:ERROR_CISCAT_PATH
ECHO Critical Error: The CisCatPath variable does not appear to be set correctly. The directory %CisCatPath% does not exist. 
GOTO EXIT

:ERROR_REPORTS_PATH
ECHO Critical Error: The directory %ReportsPath% does not exist. Ensure the ReportsPath variable is set correctly.  
GOTO EXIT

:ERROR_BENCHMARK_PATH
ECHO Critical Error: The Benchmark variable does not appear to be set correctly. The file %CisCatPath%\benchmarks\%Benchmark% does not exist. 
GOTO EXIT

:ERROR_CISCATJAR_PATH
ECHO Critical Error: CISCAT.jar does not exist at %CisCatPath%\CISCAT.jar. Ensure the CisCatPath variable is set correctly. 
GOTO EXIT
:EXIT

popd


