#!/bin/bash
echoCyan()
{
    echo -e "\e[1;36m $1 \e[0m"
}
echoGreen()
{
    echo -e "\e[1;32m $1 \e[0m"
}
echoRed()
{
    echo -e "\e[1;31m $1 \e[0m"
}
echoYellow()
{
    echo -e "\e[1;33m $1 \e[0m"
}
echoBlue()
{
    echo -e "\e[1;34m $1 \e[0m"
}
echoMagenta()
{
    echo -e "\e[1;35m $1 \e[0m"
}
runTest()
{
	for Test in ./bin/*_unit_test ; do
		echoGreen "Running $Test"
	    "$Test" > /dev/null
	    status=$?
	    if [[ status -ne 0 ]]; then
	    	"$Test"
	    	return -1
	    fi
	done
    echoGreen "PASSED"
	return 0
}


checkCoverageValues()
{
	coverageOk=1
	minimunCoverage="90.0%"
	lines=$(echo $(grep "lines" <<< "$1") | cut -d' ' -f 2)
	branches=$(echo $(grep "branches" <<< "$1") | cut -d' ' -f 2)
	functions=$(echo $(grep "functions" <<< "$1") | cut -d' ' -f 2)
	if [[ $lines < $minimunCoverage ]]; then
		echoRed "Low lines coverage $lines."
		coverageOk=0
	fi
	if [[ $branches < $minimunCoverage ]]; then
		echoRed "Low branches coverage $branches."	
		coverageOk=0
	fi
	if [[ $functions < $minimunCoverage ]]; then
		echoRed "Low functions coverage $functions."	
		coverageOk=0
	fi
	if [[ coverageOk -eq 0 ]]; then
		return -1
	fi
	echoGreen PASSED
}

getCoverage()
{
	if [[ ! -d ./coverage_report ]]; then
		mkdir ./coverage_report
	fi
	folders=""
	for Folder in ./tests/*/CMakeFiles/*.dir ; do
    folders="$folders --directory $Folder "
	done
	reportFolder=./coverage_report
	lcov $folders --capture --output-file $reportFolder/code_coverage.info -rc lcov_branch_coverage=1 --exclude "*/tests/*" --include "*/dbsync/*" -q
	coverage=$(genhtml $reportFolder/code_coverage.info --branch-coverage --output-directory $reportFolder)
	echo "Report: $reportFolder/index.html"
	checkCoverageValues "$coverage"
	return $?
}


runCppCheck()
{
	suppressList="*:*sqlite_dbengine.cpp:115"
	result=$(cppcheck --force --std=c++11 --quiet --suppressions-list=./cppcheckSuppress.txt ./ 2>&1)
	if [[ ! -z "$result" ]]; then
		cppcheck --force --std=c++11 --quiet ./
		return -1
	fi
	echoGreen "PASSED"
}

runValgrind()
{
	for Test in ./bin/*_unit_test ; do
		echoGreen "Running valgrind on $Test"
	    result=$(valgrind --leak-check=full -q --error-exitcode=1 "$Test" > /dev/null)
	    status=$?
	    if [[ status -ne 0 ]]; then
	    	return -1
	    fi
	done
	return 0
}
configDbSync()
{
	currentDir=$(pwd)
	cmake -DEXTERNAL_LIB=$currentDir/../external/
}

makeDbSync()
{
	# make clean
	make
}

readyToReview()
{
	echoYellow "====================== Compiling  ====================="
	makeDbSync
	if [[ $? -ne 0 ]]; then
		echoRed "Compiling Failed"
		return
	fi
	echoYellow "====================== Cppcheck  ====================="
	runCppCheck
	if [[ $? -ne 0 ]]; then
		echoRed "cppcheck Failed"
		return
	fi
	echoYellow "==================== Running Tests ===================="
	runTest
	if [[ $? -ne 0 ]]; then
		echoRed "Tests Failed"
		return
	fi
	echoYellow "====================== Valgrind  ====================="
	runValgrind
	if [[ $? -ne 0 ]]; then
		echoRed "Valgrind Failed"
		return
	fi	
	echoYellow "==================== Running Coverage ================="
	getCoverage
	if [[ $? -ne 0 ]]; then
		echoRed "Coverage Failed"
		return
	fi
	echoGreen "RTR PASSED: code is ready to review."
}
ScriptName="build.sh"
SwithRtr="--rtr"
SwithTests="--tests"
SwithCoverage="--coverage"
SwithMake="--make"
SwithConfig="--config"
SwithCppcheck="--cppcheck"
SwithValgrind="--valgrind"
if [[ $1 = $SwithRtr ]]; then
	readyToReview
elif [[ $1 = $SwithTests ]]; then
	runTest
elif [[ $1 = $SwithCoverage ]]; then
	getCoverage
elif [[ $1 = $SwithMake ]]; then
	makeDbSync
elif [[ $1 = $SwithConfig ]]; then
	configDbSync
elif [[ $1 = $SwithCppcheck ]]; then
	runCppCheck
elif [[ $1 = $SwithValgrind ]]; then
	runValgrind
else
	echo "Usage:"
	echo "Run all: ./$ScriptName $SwithRtr"
	echo "Config dbsync: ./$ScriptName $SwithConfig"
	echo "Make dbsync: ./$ScriptName $SwithMake"
	echo "Run dbsync tests: ./$ScriptName $SwithTests"
	echo "Run dbsync coverage: ./$ScriptName $SwithCoverage"
	echo "Run cppcheck: ./$ScriptName $SwithCppcheck"
	echo "Run Valgrind on tests: ./$ScriptName $SwithValgrind"
fi