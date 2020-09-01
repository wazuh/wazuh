import sys
import argparse
import os
import re
import glob
import subprocess

def printGreen(msg):
    print('\033[92m' + msg + '\033[0m')

def printHeader(msg):
    print('\033[95m' + msg + '\033[0m')

def printFail(msg):
    print('\033[91m' + msg + '\033[0m')

headerDic = {\
'tests':   '=================== Running Tests       ===================',\
'valgrind':'=================== Running Valgrind    ===================',\
'cppcheck':'=================== Running cppcheck    ===================',\
'make':    '=================== Compiling library   ===================',\
'clean':   '=================== Cleaning library    ===================',\
'rtr':     '=================== Running RTR checks  ===================',\
'coverage':'=================== Running Coverage    ===================',\
}    

currentBuildDir = os.path.dirname(os.path.realpath(__file__)) + "/../"

def makeLib(moduleName):
    """
    Builds the 'moduleName' lib.

    :param moduleName: Lib to be built.    
    """
    printHeader("<"+moduleName+">"+headerDic['make']+"<"+moduleName+">")
    currentDir = currentBuildDir + str(moduleName) + "/build/"
    out = subprocess.run('make -C' + currentDir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if out.returncode != 0:
        print(out.stdout)
        print(out.stderr)
        errorString = 'Error compiling library: ' + str(out.returncode)
        raise ValueError(errorString)
    printGreen(moduleName +" > [make: PASSED]")

def runTests(moduleName):
    """
    Executes the 'moduleName' lib tests.

    :param moduleName: Lib representing the tests to be executed.    
    """
    printHeader("<"+moduleName+">"+headerDic['tests']+"<"+moduleName+">")
    tests = []
    reg = re.compile(".*unit_test|.*unit_test.exe|.*integration_test|.*integration_test.exe")
    currentDir = currentBuildDir + str(moduleName) + "/build/bin/"
    objects = os.scandir(currentDir)
    for entry in objects:
        if entry.is_file() and bool(re.match(reg, entry.name)):
            tests.append(entry.name)
    for test in tests:
        out = subprocess.run(currentDir + test, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if out.returncode == 0:
            printGreen('[' + test + ': PASSED]')
        else:
            print(out.stdout)
            print(out.stderr)
            printFail('[' + test + ': FAILED]')
            errorString = 'Error Running test: ' + str(out.returncode)
            raise ValueError(errorString)

def checkCoverage(output):
    """
    Checks the coverage for the current lib being analyzed.

    :param output: Message to be shown in the stdout.
    """
    reLines = re.search("lines.*(% ).*(lines)", str(output))
    reFunctions = re.search("functions.*%", str(output))
    if reLines:
        end = reLines.group().index('%')
        start = end-4
        linesCoverage = reLines.group()[start:end]
    if reFunctions:
        end = reFunctions.group().index('%')
        start = end-4
        functionsCoverage = reFunctions.group()[start:end]
    if linesCoverage >= '90.0':
        printGreen('[Lines Coverage ' + linesCoverage + '%: PASSED]')
    else:
        printFail('[Lines Coverage ' + linesCoverage + '%: LOW]')
        errorString = 'Low lines coverage: ' + linesCoverage
        raise ValueError(errorString)
    if functionsCoverage >= '90.0':
        printGreen('[Functions Coverage ' + functionsCoverage + '%: PASSED]')
    else:
        printFail('[Functions Coverage ' + functionsCoverage + '%: LOW]')
        errorString = 'Low functions coverage: ' + functionsCoverage
        raise ValueError(errorString)

def runValgrind(moduleName):
    """
    Executes valgrind tool under the 'moduleName' lib unit and integration tests.

    :param moduleName: Lib to be analyzed using valgrind tool.
    """
    printHeader("<"+moduleName+">"+headerDic['valgrind']+"<"+moduleName+">")
    tests = []
    reg = re.compile(".*unit_test|.*unit_test.exe|.*integration_test|.*integration_test.exe")
    currentDir = currentBuildDir + str(moduleName) + "/build/bin/"
    objects = os.scandir(currentDir)
    for entry in objects:
        if entry.is_file() and bool(re.match(reg, entry.name)):
            tests.append(entry.name)
    valgrindCommand = "valgrind --leak-check=full --show-leak-kinds=all -q --error-exitcode=1 " + currentDir
    for test in tests:
        out = subprocess.run(valgrindCommand + test, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if out.returncode == 0:
            printGreen('[' + test + ': PASSED]')
        else:
            print(out.stdout)
            print(out.stderr)
            printFail('[' + test + ': FAILED]')
            errorString = 'Error Running valgrind: ' + str(out.returncode)
            raise ValueError(errorString)

def runCoverage(moduleName):
    """
    Executes code coverage under 'moduleName' lib unit tests.

    :param moduleName: Lib to be analyzed using gcov and lcov tools.
    """
    currentDir = currentBuildDir + str(moduleName)
    reportFolder = currentDir + '/coverage_report'
    folders = ''
    printHeader("<"+moduleName+">"+headerDic['coverage']+"<"+moduleName+">")
    if not os.path.exists(reportFolder):
        os.mkdir(reportFolder)
    for dir in glob.glob(currentDir + "/build/tests/*/CMakeFiles/*.dir"):
        folders += '--directory ' + dir + ' '
    coverageCommand = 'lcov ' + folders + ' --capture --output-file ' + reportFolder + '/code_coverage.info -rc lcov_branch_coverage=0 --exclude "*/tests/*" --include "*/'+moduleName+'/*" -q'
    out = subprocess.run(coverageCommand, stdout=subprocess.PIPE, shell=True)
    if out.returncode == 0:
        printGreen('[lcov info: GENERATED]')
    else:
        print(out.stdout)
        printFail('[lcov: FAILED]')
        errorString = 'Error Running cppcheck: ' + str(out.returncode)
        raise ValueError(errorString)
    genhtmlCommand = 'genhtml ' + reportFolder + '/code_coverage.info --branch-coverage --output-directory ' + reportFolder

    out = subprocess.run(genhtmlCommand, stdout=subprocess.PIPE, shell=True)
    if out.returncode == 0:
        printGreen('[genhtml info: GENERATED]')
        printGreen('Report: ' + reportFolder + '/index.html')
    else:
        print(out.stdout)
        printFail('[genhtml: FAILED]')
        errorString = 'Error Running genhtml: ' + str(out.returncode)
        raise ValueError(errorString)
    checkCoverage(out.stdout)

def runCppCheck(moduleName):
    """
    Executes cppcheck static analysis tool under 'moduleName' lib code.

    :param moduleName: Lib to be analyzed using cppcheck static analysis tool.
    """
    printHeader("<"+moduleName+">"+headerDic['cppcheck']+"<"+moduleName+">")
    currentDir = currentBuildDir + str(moduleName)
    cppcheckCommand = "cppcheck --force --std=c++11 --quiet --suppressions-list=" + currentDir + "/cppcheckSuppress.txt " + currentDir
    out = subprocess.run(cppcheckCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0 and not out.stderr:
        printGreen('[Cppcheck: PASSED]')
    else:
        print(out.stderr)
        printFail('[Cppcheck: FAILED]')
        errorString = 'Error Running cppcheck: ' + str(out.returncode)
        raise ValueError(errorString)

def cleanLib(moduleName):
    """
    Cleans the 'moduleName' generated files.

    :param moduleName: Lib to be clean.
    """
    currentDir = currentBuildDir + str(moduleName) + "/build"
    os.system('make clean -C' + currentDir)

def runReadyToReview(moduleName):
    """
    Executes all needed checks under the 'moduleName' lib.

    :param moduleName: Lib to be built and analyzed.
    """
    printHeader("<"+moduleName+">"+headerDic['rtr']+"<"+moduleName+">")
    runCppCheck(str(moduleName))
    makeLib(str(moduleName))
    runTests(str(moduleName))
    runValgrind(str(moduleName))
    runCoverage(str(moduleName))
    printGreen("<"+moduleName+">"+"[RTR: PASSED]"+"<"+moduleName+">")