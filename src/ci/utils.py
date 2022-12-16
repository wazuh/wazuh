# Copyright (C) 2015, Wazuh Inc.
# All right reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#
import os
import re
import glob
import subprocess
from pathlib import Path


def printGreen(msg):
    print('\033[92m' + msg + '\033[0m')


def printHeader(moduleName, header_key):
    msg = f"<{moduleName}>{headerDic[header_key]}<{moduleName}>"
    print('\033[95m' + msg + '\033[0m')


def printFail(msg):
    print('\033[91m' + msg + '\033[0m')


headerDic = {
    'tests':            '=================== Running Tests       ===================',
    'valgrind':         '=================== Running Valgrind    ===================',
    'cppcheck':         '=================== Running cppcheck    ===================',
    'asan':             '=================== Running ASAN        ===================',
    'scanbuild':        '=================== Running Scanbuild   ===================',
    'testtool':         '=================== Running TEST TOOL   ===================',
    'cleanfolder':      '=================== Clean build Folders ===================',
    'configurecmake':   '=================== Running CMake Conf  ===================',
    'make':             '=================== Compiling library   ===================',
    'clean':            '=================== Cleaning library    ===================',
    'rtr':              '=================== Running RTR checks  ===================',
    'coverage':         '=================== Running Coverage    ===================',
    'AStyle':           '=================== Running AStyle      ===================',
}

smokeTestsDic = {
    'wazuh_modules/syscollector': [
        {
            'test_tool_name': 'syscollector_test_tool',
            'is_smoke_with_configuration': False,
            'args': [
                '10'
            ]
        }
    ],
    'shared_modules/dbsync': [
        {
            'test_tool_name': 'dbsync_test_tool',
            'is_smoke_with_configuration': True,
            'args': [
                '-c config.json',
                '-a snapshotsUpdate/insertData.json,snapshotsUpdate/updateWithSnapshot.json',
                '-o ./output'
            ]
        },
        {
            'test_tool_name': 'dbsync_test_tool',
            'is_smoke_with_configuration': True,
            'args': [
                '-c config.json',
                '-a InsertionUpdateDeleteSelect/inputSyncRowInsert.json,InsertionUpdateDeleteSelect/inputSyncRowModified.json,InsertionUpdateDeleteSelect/deleteRows.json,InsertionUpdateDeleteSelect/inputSelectRows.json',
                '-o ./output'
            ]
        },
        {
            'test_tool_name': 'dbsync_test_tool',
            'is_smoke_with_configuration': True,
            'args': [
                '-c config.json',
                '-a txnOperation/createTxn.json,txnOperation/inputSyncRowInsertTxn.json,txnOperation/inputSyncRowModifiedTxn.json,txnOperation/closeTxn.json',
                '-o ./output'
            ]
        },
        {
            'test_tool_name': 'dbsync_test_tool',
            'is_smoke_with_configuration': True,
            'args': [
                '-c config.json',
                '-a triggerActions/insertDataProcesses.json,triggerActions/insertDataSocket.json,triggerActions/addTableRelationship.json,triggerActions/deleteRows.json',
                '-o ./output'
            ]
        }
    ],
    'shared_modules/rsync': [
        {
            'test_tool_name': 'rsync_test_tool',
            'is_smoke_with_configuration': False,
            'args': []
        }
    ],
    'data_provider': [
        {
            'test_tool_name': 'sysinfo_test_tool',
            'is_smoke_with_configuration': False,
            'args': []
        }
    ]
}

deleteFolderDic = {
    'wazuh_modules/syscollector':   ['build', 'smokeTests/output'],
    'shared_modules/dbsync':        ['build', 'smokeTests/output'],
    'shared_modules/rsync':         ['build', 'smokeTests/output'],
    'data_provider':                ['build', 'smokeTests/output'],
    'shared_modules/utils':         ['build'],
}

currentBuildDir = Path(__file__).parent


def currentDirPath(moduleName):
    """
    Gets the current dir path based on 'moduleName'

    :param moduleName: Lib to get the path of.
    :return Lib dir path
    """
    currentDir = os.path.join(currentBuildDir.parent, str(moduleName))
    if str(moduleName) == 'shared_modules/utils':
        currentDir = os.path.join(currentDir, 'tests/')

    return currentDir


def currentDirPathBuild(moduleName):
    """
    Gets the current dir path build based on 'moduleName'

    :param moduleName: Lib to get the path of.
    :return Lib dir path build folder
    """
    currentDir = currentDirPath(moduleName)
    return os.path.join(currentDir, 'build')


def makeLib(moduleName):
    """
    Builds the 'moduleName' lib.

    :param moduleName: Lib to be built.
    """
    command = f'make -C {currentDirPathBuild(moduleName)}'
    printHeader(moduleName, 'make')

    out = subprocess.run(command, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)
    if out.returncode != 0:
        print(command)
        print(out.stdout)
        print(out.stderr)
        errorString = f'Error compiling library: {str(out.returncode)}'
        raise ValueError(errorString)
    printGreen(f'{moduleName} > [make: PASSED]')


def runTests(moduleName):
    """
    Executes the 'moduleName' lib tests.

    :param moduleName: Lib representing the tests to be executed.
    """
    printHeader(moduleName, 'tests')
    tests = []
    reg = re.compile(
        ".*unit_test|.*unit_test.exe|.*integration_test|.*integration_test.exe")
    currentDir = currentDirPathBuild(moduleName)

    if not moduleName == 'shared_modules/utils':
        currentDir = os.path.join(currentDirPathBuild(moduleName), 'bin')

    objects = os.scandir(currentDir)
    for entry in objects:
        if entry.is_file() and bool(re.match(reg, entry.name)):
            tests.append(entry.name)
    for test in tests:
        out = subprocess.run(os.path.join(currentDir, test), stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        if out.returncode == 0:
            printGreen(f'[{test}: PASSED]')
        else:
            print(out.stdout)
            print(out.stderr)
            printFail(f'[{test}: FAILED]')
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
        start = reLines.group()[0:end].rindex(' ') + 1
        linesCoverage = reLines.group()[start:end]
    if reFunctions:
        end = reFunctions.group().index('%')
        start = reFunctions.group().rindex(' ') + 1
        functionsCoverage = reFunctions.group()[start:end]
    if float(linesCoverage) >= 90.0:
        printGreen(f'[Lines Coverage {linesCoverage}%: PASSED]')
    else:
        printFail(f'[Lines Coverage {linesCoverage}%: LOW]')
        errorString = f'Low lines coverage: {linesCoverage}'
        raise ValueError(errorString)
    if float(functionsCoverage) >= 90.0:
        printGreen(f'[Functions Coverage {functionsCoverage}%: PASSED]')
    else:
        printFail(f'[Functions Coverage {functionsCoverage}%: LOW]')
        errorString = f'Low functions coverage: {functionsCoverage}'
        raise ValueError(errorString)


def runValgrind(moduleName):
    """
    Executes valgrind tool under the 'moduleName' lib unit and integration tests.

    :param moduleName: Lib to be analyzed using valgrind tool.
    """
    printHeader(moduleName, 'valgrind')
    tests = []
    reg = re.compile(
        ".*unit_test|.*unit_test.exe|.*integration_test|.*integration_test.exe")
    currentDir = ""
    if str(moduleName) == 'shared_modules/utils':
        currentDir = os.path.join(currentDirPath(moduleName), 'build')
    else:
        currentDir = os.path.join(currentDirPath(moduleName), 'build/bin')

    objects = os.scandir(currentDir)
    for entry in objects:
        if entry.is_file() and bool(re.match(reg, entry.name)):
            tests.append(entry.name)
    valgrindCommand = "valgrind --leak-check=full --show-leak-kinds=all -q --error-exitcode=1 " + currentDir

    for test in tests:
        out = subprocess.run(os.path.join(valgrindCommand, test), stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        if out.returncode == 0:
            printGreen(f'[{test} : PASSED]')
        else:
            print(out.stdout)
            print(out.stderr)
            printFail(f'[{test} : FAILED]')
            errorString = 'Error Running valgrind: ' + str(out.returncode)
            raise ValueError(errorString)


def runCoverage(moduleName):
    """
    Executes code coverage under 'moduleName' lib unit tests.

    :param moduleName: Lib to be analyzed using gcov and lcov tools.
    """
    currentDir = currentDirPath(moduleName)
    if moduleName == 'shared_modules/utils':
        reportFolder = os.path.join(moduleName, 'coverage_report')
    else:
        reportFolder = os.path.join(currentDir, 'coverage_report')

    includeDir = Path(currentDir)
    moduleCMakeFiles = ""

    if moduleName == 'shared_modules/utils':
        moduleCMakeFiles = os.path.join(currentDir, '*/CMakeFiles/*.dir')
        includeDir = includeDir.parent
    else:
        moduleCMakeFiles = os.path.join(
            currentDir, 'build/tests/*/CMakeFiles/*.dir')

    printHeader(moduleName, 'coverage')
    folders = ''
    if not os.path.exists(reportFolder):
        os.mkdir(reportFolder)

    for dir in glob.glob(moduleCMakeFiles):
        folders += '--directory ' + dir + ' '

    coverageCommand = f'lcov {folders} --capture --output-file {reportFolder}/code_coverage.info -rc ' \
                      f'lcov_branch_coverage=0 --exclude="*/tests/*" --include "{includeDir}/*" -q'

    out = subprocess.run(coverageCommand, stdout=subprocess.PIPE, shell=True)

    if out.returncode == 0:
        printGreen('[lcov info: GENERATED]')
    else:
        print(out.stdout)
        printFail('[lcov: FAILED]')
        errorString = 'Error Running lcov: ' + str(out.returncode)
        raise ValueError(errorString)

    genhtmlCommand = f'genhtml {reportFolder}/code_coverage.info --branch-coverage --output-directory {reportFolder}'

    out = subprocess.run(genhtmlCommand, stdout=subprocess.PIPE, shell=True)
    if out.returncode == 0:
        printGreen('[genhtml info: GENERATED]')
        printGreen(f'Report: {reportFolder}/index.html')
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
    printHeader(moduleName, 'cppcheck')

    currentDir = currentDirPath(moduleName)
    cppcheckCommand = f'cppcheck --force --std=c++14 --quiet {currentDir}'

    out = subprocess.run(cppcheckCommand, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)
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
    currentDir = currentDirPathBuild(moduleName)
    os.system('make clean -C' + currentDir)


def cleanFolder(moduleName, additionalFolder):

    currentDir = currentDirPath(moduleName)
    cleanFolderCommand = f'rm -rf {os.path.join(currentDir, additionalFolder)}'

    if deleteFolderDic[moduleName].count(additionalFolder) > 0:
        out = subprocess.run(
            cleanFolderCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if out.returncode == 0 and not out.stderr:
            printGreen('[Cleanfolder: PASSED]')
        else:
            print(cleanFolderCommand)
            print(out.stderr)
            printFail('[Cleanfolder: FAILED]')
            errorString = 'Error Running Cleanfolder: ' + str(out.returncode)
            raise ValueError(errorString)
    else:
        printFail('[Cleanfolder: FAILED]')
        errorString = 'Error Running Cleanfolder: additional folder not exist in delete folder dictionary.'
        raise ValueError(errorString)


def cleanAll():
    out = subprocess.run("make clean", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0:
        printGreen('[CleanAll: PASSED]')
    else:
        print("make clean")
        print(out.stderr)
        printFail('[CleanAll: FAILED]')
        errorString = 'Error Running CleanAll: ' + str(out.returncode)
        raise ValueError(errorString)


def cleanInternals():
    out = subprocess.run("make clean-internals", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0:
        printGreen('[CleanInternals: PASSED]')
    else:
        print("make clean-internals")
        print(out.stderr)
        printFail('[CleanInternals: FAILED]')
        errorString = 'Error Running CleanInternals: ' + str(out.returncode)
        raise ValueError(errorString)


def cleanExternals():
    out = subprocess.run("rm -rf ./external/*", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0 and not out.stderr:
        printGreen('[CleanExternals: PASSED]')
    else:
        print("rm -rf ./external/*")
        print(out.stderr)
        printFail('[CleanExternals: FAILED]')
        errorString = 'Error Running CleanExternals: ' + str(out.returncode)
        raise ValueError(errorString)


def makeDeps(targetName, srcOnly):
    makeDepsCommand = "make deps TARGET=" + targetName
    if srcOnly:
        makeDepsCommand += " EXTERNAL_SRC_ONLY=yes"
    out = subprocess.run(makeDepsCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0:
        printGreen('[MakeDeps: PASSED]')
    else:
        print(makeDepsCommand)
        print(out.stderr)
        printFail('[MakeDeps: FAILED]')
        errorString = 'Error Running MakeDeps: ' + str(out.returncode)
        raise ValueError(errorString)


def makeTarget(targetName, tests, debug):
    makeTargetCommand = "make TARGET=" + targetName
    if tests:
        makeTargetCommand += " TEST=1"
    if debug:
        makeTargetCommand += " DEBUG=1"

    out = subprocess.run(makeTargetCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0:
        printGreen('[MakeTarget: PASSED]')
    else:
        print(makeTargetCommand)
        print(out.stderr)
        printFail('[MakeTarget: FAILED]')
        errorString = 'Error Running MakeTarget: ' + str(out.returncode)
        raise ValueError(errorString)


def configureCMake(moduleName, debugMode, testMode, withAsan):
    printHeader(moduleName, 'configurecmake')
    currentModuleNameDir = currentDirPath(moduleName)
    currentPathDir = currentDirPathBuild(moduleName)

    if not os.path.exists(currentPathDir):
        os.mkdir(currentPathDir)

    configureCMakeCommand = "cmake -S" + currentModuleNameDir + " -B" + currentPathDir

    if debugMode:
        configureCMakeCommand += " -DCMAKE_BUILD_TYPE=Debug"

    if testMode:
        configureCMakeCommand += " -DUNIT_TEST=1"

    if withAsan:
        configureCMakeCommand += " -DFSANITIZE=1"

    out = subprocess.run(
        configureCMakeCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0 and not out.stderr:
        printGreen('[ConfigureCMake: PASSED]')
    else:
        print(configureCMakeCommand)
        print(out.stderr)
        printFail('[ConfigureCMake: FAILED]')
        errorString = 'Error Running ConfigureCMake: ' + str(out.returncode)
        raise ValueError(errorString)


def runTestTool(moduleName, testToolCommand, isSmokeTest=False):
    printHeader('TESTTOOL', 'testtool')
    printGreen(testToolCommand)
    cwd = os.getcwd()

    if isSmokeTest:
        currentmoduleNameDir = currentDirPath(moduleName)
        output_folder = os.path.join(currentmoduleNameDir, 'smokeTests/output')
        os.chdir(os.path.join(currentmoduleNameDir, 'smokeTests'))
        cleanFolder(moduleName, 'smokeTests/output')
        if not os.path.exists(output_folder):
            os.mkdir(output_folder)

    out = subprocess.run(testToolCommand, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)

    os.chdir(cwd)

    if out.returncode == 0 and not out.stderr:
        printGreen('[TestTool: PASSED]')
    else:
        print(testToolCommand)
        print(out.stderr)
        printFail('[TestTool: FAILED]')
        errorString = 'Error Running TestTool: ' + str(out.returncode)
        raise ValueError(errorString)


def runASAN(moduleName):
    """
    Executes Address Sanitizer dynamic analysis tool under 'moduleName' lib code.

    :param moduleName: Lib to be analyzed using ASAN dynamic analysis tool.
    """
    printHeader(moduleName, 'asan')
    cleanFolder(str(moduleName), "build")
    configureCMake(str(moduleName), True, False, True)
    makeLib(str(moduleName))

    for element in smokeTestsDic[moduleName]:
        path = os.path.join(currentDirPathBuild(moduleName),
                            'bin', element['test_tool_name'])
        args = ' '.join(element['args'])
        testToolCommand = f'{path} {args}'
        runTestTool(str(moduleName), testToolCommand,
                    element['is_smoke_with_configuration'])

    printGreen(f'<{moduleName}>[ASAN: PASSED]<{moduleName}>')


def runScanBuild(targetName):
    """
    Executes scan-build for 'targetName'.
    :param targetName: Target to be analyzed using scan-build analysis tool.
    """
    printHeader(targetName, 'scanbuild')
    cleanAll()
    cleanExternals()
    if targetName == "winagent":
        makeDeps(targetName, True)
        makeTarget("winagent", False, True)
        cleanInternals()
        scanBuildCommand = 'scan-build-12 --status-bugs --use-cc=/usr/bin/i686-w64-mingw32-gcc \
                            --use-c++=/usr/bin/i686-w64-mingw32-g++-posix --analyzer-target=i686-w64-mingw32 \
                            --force-analyze-debug-code make TARGET=winagent DEBUG=1 -j4'
    else:
        makeDeps(targetName, False)
        scanBuildCommand = 'scan-build-12 --status-bugs --force-analyze-debug-code --exclude external/ make TARGET=' + targetName + ' DEBUG=1 -j4'

    out = subprocess.run(scanBuildCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

    if out.returncode == 0:
        printGreen('[ScanBuild: PASSED]')
    else:
        printFail('[ScanBuild: FAILED]')
        print(scanBuildCommand)
        if out.returncode == 1:
            print(out.stdout)
        else:
            print(out.stderr)
        printFail('[SCANBUILD: FAILED]')
        errorString = 'Error Running Scan-build: ' + str(out.returncode)
        raise ValueError(errorString)

    printGreen("<"+targetName+">"+"[SCANBUILD: PASSED]"+"<"+targetName+">")


def _getFoldersToAStyle(moduleName):
    """
    Returns the folders to be analyzed with AStyle coding style analysis tool.

    :param moduleName: Lib to be analyzed using AStyle coding style analysis tool.
    :return specific folders and files to be analyzed.
    """
    printHeader(moduleName, 'AStyle')
    cleanFolder(str(moduleName), "build")

    foldersToScan = ""
    if str(moduleName) == 'shared_modules/utils':
        foldersToScan = f'{moduleName}/../*.h {moduleName}/*.cpp'
    else:
        foldersToScan = f'{moduleName}/*.h {moduleName}/*.cpp'
    return foldersToScan


def runAStyleCheck(moduleName):
    """
    Executes AStyle coding style analysis tool under 'moduleName' lib code failing when
    one or more files need to be modified.

    :param moduleName: Lib to be analyzed using AStyle coding style analysis tool.
    """
    foldersToScan = _getFoldersToAStyle(moduleName)
    astyleCommand = "astyle --options=ci/input/astyle.config --dry-run " + foldersToScan
    out = subprocess.run(astyleCommand, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)

    if out.returncode == 0 and not out.stderr:
        stdoutString = str(out.stdout)

        if (stdoutString.find("Formatted") != -1):
            printFail('One or more files do not follow the Coding Style convention.')
            printFail(f'Execute astyle --options=ci/input/astyle.config {moduleName}/*.h {moduleName}/*.cpp for further'
                      f'information.')

            printFail('[AStyle: FAILED]')
            raise ValueError("Code is not complaint with the expected guidelines")
        else:
            printGreen(f'<{moduleName}>[AStyle Check: PASSED]<{moduleName}>')
    else:
        print(out.stderr)
        printFail('[AStyle Check: FAILED]')
        errorString = 'Error Running AStyle: ' + str(out.returncode)
        raise ValueError(errorString)


def runAStyleFormat(moduleName):
    """
    Executes AStyle coding style analysis tool under 'moduleName' lib code formatting
    all needed files.

    :param moduleName: Lib to be analyzed using AStyle coding style analysis tool.
    """
    foldersToScan = _getFoldersToAStyle(moduleName)
    astyleCommand = f'astyle --options=ci/input/astyle.config {foldersToScan}'
    out = subprocess.run(astyleCommand, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)

    if out.returncode == 0 and not out.stderr:
        printGreen(f'<{moduleName}>[AStyle Format: PASSED]<{moduleName}>')
    else:
        print(out.stderr)
        printFail('[AStyle Format: FAILED]')
        errorString = 'Error Running AStyle Format: ' + str(out.returncode)
        raise ValueError(errorString)


def runReadyToReview(moduleName):
    """
    Executes all needed checks under the 'moduleName' lib.

    :param moduleName: Lib to be built and analyzed.
    """

    printHeader(moduleName, 'rtr')
    runCppCheck(str(moduleName))
    cleanFolder(str(moduleName), "build")
    configureCMake(str(moduleName), True, (False, True)[
                   str(moduleName) != 'shared_modules/utils'], False)
    makeLib(str(moduleName))
    runTests(str(moduleName))
    runValgrind(str(moduleName))
    runCoverage(str(moduleName))
    runAStyleCheck(str(moduleName))
    if str(moduleName) != 'shared_modules/utils':
        runASAN(moduleName)

    printGreen(f'<{moduleName}>[RTR: PASSED]<{moduleName}>')
