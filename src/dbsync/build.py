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
'config':  '=================== Configuring library ===================',\
'rtr':     '=================== Running RTR checks  ===================',\
'coverage':'=================== Running Coverage    ===================',\
}

def runTests():
    printHeader(headerDic['tests'])
    tests = []
    reg = re.compile(".*unit_test|.*unit_test.exe|.*integration_test|.*integration_test.exe")
    currentDir = os.path.dirname(os.path.realpath(__file__)) + "/bin/"
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


def runCoverage():
    currentDir = os.path.dirname(os.path.realpath(__file__))
    reportFolder = currentDir + '/coverage_report'
    folders = ''
    printHeader(headerDic['coverage'])
    if not os.path.exists(reportFolder):
        os.mkdir(reportFolder)
    for dir in glob.glob(currentDir + "/tests/*/CMakeFiles/*.dir"):
        folders += '--directory ' + dir + ' '
    coverageCommand = 'lcov ' + folders + ' --capture --output-file ' + reportFolder + '/code_coverage.info -rc lcov_branch_coverage=0 --exclude "*/tests/*" --include "*/dbsync/*" -q'
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

def runCppCheck():
    printHeader(headerDic['cppcheck'])
    currentDir = os.path.dirname(os.path.realpath(__file__))
    cppcheckCommand = "cppcheck --force --std=c++11 --quiet --suppressions-list=" + currentDir + "/cppcheckSuppress.txt " + currentDir
    out = subprocess.run(cppcheckCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0 and not out.stderr:
        printGreen('[Cppcheck: PASSED]')
    else:
        print(out.stderr)
        printFail('[Cppcheck: FAILED]')
        errorString = 'Error Running cppcheck: ' + str(out.returncode)
        raise ValueError(errorString)

def runReadyToReview():
    printHeader(headerDic['rtr'])
    runCppCheck()
    makeLib()
    runTests()
    runValgrind()
    runCoverage()
    printGreen("[RTR: PASSED]")

def runValgrind():
    printHeader(headerDic['valgrind'])
    tests = []
    reg = re.compile(".*unit_test|.*unit_test.exe|.*integration_test|.*integration_test.exe")
    currentDir = os.path.dirname(os.path.realpath(__file__)) + "/bin/"
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

def makeLib():
    printHeader(headerDic['make'])
    currentDir = os.path.dirname(os.path.realpath(__file__))
    out = subprocess.run('make -C' + currentDir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if out.returncode != 0:
        print(out.stdout)
        print(out.stderr)
        errorString = 'Error compiling library: ' + str(out.returncode)
        raise ValueError(errorString)
    printGreen("[make: PASSED]")
        

def cleanLib():
    currentDir = os.path.dirname(os.path.realpath(__file__))
    os.system('make clean -C' + currentDir)

def configLinux(type, tests):
    currentDir = os.path.dirname(os.path.realpath(__file__))
    cmakeCommand = "cmake -DEXTERNAL_LIB=" + currentDir + "/../external/ -DCMAKE_BUILD_TYPE=" + type
    if tests == 'ON':
        cmakeCommand += " -DUNIT_TEST=ON "
    else:
        cmakeCommand += " "
    cmakeCommand += currentDir
    print(cmakeCommand)
    out = subprocess.run(cmakeCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if out.returncode != 0:
        print(out.stdout)
        print(out.stderr)
        errorString = 'Error configuring library: ' + str(out.returncode)
        raise ValueError(errorString)
    printGreen("[CONFIGURED: Linux|" + type + "|TEST=" + tests + "]")

def configWin(type, tests):
    print("win build")

def configMac(type, tests):
    print("Mac build")

def configLib(args):
    printHeader(headerDic['config'])
    SupportedOs = ['win','linux','mac']
    SupportedTypes = ['Release','Debug']
    SupportedTests = ['ON','OFF']
    os = ''
    builType = ''
    tests = ''
    for arg in args:
        if arg in SupportedOs:
            os = arg  
        elif arg in SupportedTypes:
            builType = arg
        elif arg in SupportedTests:
            tests = arg
        else:
            raise ValueError('invalid config ' + arg)

    if os == 'win':
        configWin(builType, tests)
    elif os == 'linux':
        configLinux(builType, tests)
    else:
        configMac(builType, tests)

if __name__ == "__main__":
    Choices = ['win','linux','mac', 'release','debug','on','off']
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    parser.add_argument("-t", "--tests", action="store_true", help="Run tests (should be configured with TEST=on)")
    parser.add_argument("-c", "--coverage", action="store_true", help="Collect tests coverage and generates report")
    parser.add_argument("-r", "--readytoreview", action="store_true", help="Run all the quality checks needed to create a PR")
    parser.add_argument("-v", "--valgrind", action="store_true", help="Run valgrind on tests")
    parser.add_argument("-m", "--make", action="store_true", help="Compile the lib")
    parser.add_argument("--clean", action="store_true", help="Clean the lib")
    parser.add_argument("--cppcheck", action="store_true", help="Run cppcheck on the code")
    parser.add_argument("--config", nargs=3, metavar=('OS','TYPE','TEST'),  help="Configure the lib. OS=win|linux|mac TYPE=Release|Debug TEST=ON|OFF")
    args = parser.parse_args()
    if args.tests:
        runTests()
    elif args.coverage:
        runCoverage()
    elif args.readytoreview:
        runReadyToReview()
    elif args.valgrind:
        runValgrind()
    elif args.make:
        makeLib()
    elif args.clean:
        cleanLib()
    elif args.cppcheck:
        runCppCheck()
    elif args.config:
        configLib(args.config)
    else:
        parser.print_help()