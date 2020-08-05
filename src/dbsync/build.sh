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
    echoGreen "[PASSED]"
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
    echoGreen "Lines Coverage: $lines"
    echoGreen "Functions Coverage: $functions"
    echoGreen [PASSED]
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
    lcov $folders --capture --output-file $reportFolder/code_coverage.info -rc lcov_branch_coverage=0 --exclude "*/tests/*" --include "*/dbsync/*" -q
    coverage=$(genhtml $reportFolder/code_coverage.info --branch-coverage --output-directory $reportFolder)
    echo "Report: $reportFolder/index.html"
    checkCoverageValues "$coverage"
    return $?
}


runCppCheck()
{
    result=$(cppcheck --force --std=c++11 --quiet --suppressions-list=./cppcheckSuppress.txt ./ 2>&1)
    if [[ ! -z "$result" ]]; then
        cppcheck --force --std=c++11 --quiet ./
        return -1
    fi
    echoGreen "[PASSED]"
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
    echoGreen "[PASSED]"
    return 0
}
configDbSync()
{
    currentDir=$(pwd)
    cmake -DEXTERNAL_LIB=$currentDir/../external/ -DCMAKE_BUILD_TYPE=Debug -DUNIT_TEST=ON .
}

makeDbSync()
{
    make
    if [[ $? -ne 0 ]]; then
        return -1
    fi
    echoGreen "[PASSED]"
}

remakeDbSync()
{
    make clean
    make
    if [[ $? -ne 0 ]]; then
        return -1
    fi
    echoGreen "[PASSED]"
}
readyToReview()
{
    echoYellow "====================== Compiling  ====================="
    makeDbSync
    if [[ $? -ne 0 ]]; then
        echoRed "[FAILED]"
        return 1
    fi
    echoYellow "====================== Cppcheck  ====================="
    runCppCheck
    if [[ $? -ne 0 ]]; then
        echoRed "[FAILED]"
        return 2
    fi
    echoYellow "==================== Running Tests ===================="
    runTest
    if [[ $? -ne 0 ]]; then
        echoRed "[FAILED]"
        return 3
    fi
    echoYellow "====================== Valgrind  ====================="
    runValgrind
    if [[ $? -ne 0 ]]; then
        echoRed "[FAILED]"
        return 4
    fi
    echoYellow "==================== Running Coverage ================="
    getCoverage
    if [[ $? -ne 0 ]]; then
        echoRed "[FAILED]"
        return 5
    fi
    echo ""
    echoGreen "===> RTR PASSED: code is ready to review <==="
    echo ""
}

showHelp()
{
    echo "Usage:"
    echo "./$ScriptName $SwitchHelp      :   Show this help."
    echo "./$ScriptName $SwitchRtr       :   Ready to Review checks."
    echo "./$ScriptName $SwitchConfig    :   Config dbsync."
    echo "./$ScriptName $SwitchMake      :   Make dbsync."
    echo "./$ScriptName $SwitchReMake    :   Clean and Make dbsync."
    echo "./$ScriptName $SwitchTests     :   Tests."
    echo "./$ScriptName $SwitchCoverage  :   Coverage."
    echo "./$ScriptName $SwitchCppcheck  :   cppcheck."
    echo "./$ScriptName $SwitchValgrind  :   Valgrind on tests."
}

ScriptName="build.sh"
SwitchHelp="--help"
SwitchRtr="--rtr"
SwitchTests="--tests"
SwitchCoverage="--coverage"
SwitchMake="--make"
SwitchReMake="--remake"
SwitchConfig="--config"
SwitchCppcheck="--cppcheck"
SwitchValgrind="--valgrind"

if [[ $1 = $SwitchRtr ]]; then
    readyToReview
elif [[ $1 = $SwitchTests ]]; then
    runTest
elif [[ $1 = $SwitchCoverage ]]; then
    getCoverage
elif [[ $1 = $SwitchMake ]]; then
    makeDbSync
elif [[ $1 = $SwitchReMake ]]; then
    remakeDbSync
elif [[ $1 = $SwitchConfig ]]; then
    configDbSync
elif [[ $1 = $SwitchCppcheck ]]; then
    runCppCheck
elif [[ $1 = $SwitchValgrind ]]; then
    runValgrind
elif [[ $1 = $SwitchHelp ]]; then
    showHelp
else
    showHelp
fi
