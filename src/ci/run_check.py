# Wazuh Syscheck
# Copyright (C) 2015, Wazuh Inc.
# March 28, 2022.

# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


import glob
import json
import shutil
import os
from pathlib import Path
import re
import subprocess
from ci import utils
from ci import build_tools


CURRENT_DIR = Path(__file__).parent


def runTests(moduleName):
    """
    Executes the 'moduleName' lib tests.

    :param moduleName: Lib representing the tests to be executed.
    """
    utils.printHeader(moduleName, "tests")
    tests = []
    reg = re.compile(".*unit_test|.*unit_test.exe|.*integration_test\
                      |.*interface_test|.*integration_test.exe\
                      |.*interface_test.exe")
    currentDir = utils.currentDirPathBuild(moduleName)

    if not moduleName == "shared_modules/utils":
        currentDir = os.path.join(utils.currentDirPathBuild(moduleName), "bin")

    objects = os.scandir(currentDir)
    for entry in objects:
        if entry.is_file() and bool(re.match(reg, entry.name)):
            tests.append(entry.name)
    for test in tests:
        out = subprocess.run(os.path.join(currentDir, test),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=True)
        if out.returncode == 0:
            utils.printGreen(msg="[{}: PASSED]".format(test))
        else:
            print(out.stdout)
            print(out.stderr)
            utils.printFail("[{}: FAILED]".format(test))
            errorString = "Error Running test: {}".format(out.returncode)
            raise ValueError(errorString)
    print("\n")
    utils.printGreen(msg="[All tests: PASSED]", module=moduleName)


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
        utils.printGreen(msg="[Lines Coverage {}%: PASSED]"
                         .format(linesCoverage))
    else:
        utils.printFail("[Lines Coverage {}%: LOW]".format(linesCoverage))
        errorString = "Low lines coverage: {}".format(linesCoverage)
        raise ValueError(errorString)
    if float(functionsCoverage) >= 90.0:
        utils.printGreen(msg="[Functions Coverage {}%: PASSED]"
                         .format(functionsCoverage))
    else:
        utils.printFail("[Functions Coverage {functionsCoverage}%: LOW]")
        errorString = "Low functions coverage: {}".format(functionsCoverage)


def runValgrind(moduleName):
    """
    Executes valgrind tool under the 'moduleName'
    lib unit and integration tests.

    :param moduleName: Lib to be analyzed using valgrind tool.
    """
    utils.printHeader(moduleName, "valgrind")
    tests = []
    reg = re.compile(".*unit_test|.*unit_test.exe|.*integration_test\
                     |.*interface_test|.*integration_test.exe\
                     |.*interface_test.exe")
    currentDir = ""
    if str(moduleName) == "shared_modules/utils":
        currentDir = os.path.join(utils.currentDirPath(moduleName), "build")
    else:
        currentDir = os.path.join(
            utils.currentDirPath(moduleName), "build/bin")

    objects = os.scandir(currentDir)
    for entry in objects:
        if entry.is_file() and bool(re.match(reg, entry.name)):
            tests.append(entry.name)
    valgrindCommand = "valgrind --leak-check=full --show-leak-kinds=all \
                       -q --error-exitcode=1 {}".format(currentDir)

    for test in tests:
        out = subprocess.run(os.path.join(valgrindCommand, test),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        if out.returncode == 0:
            utils.printGreen(msg="[{} : PASSED]".format(test))
        else:
            print(out.stdout)
            print(out.stderr)
            utils.printFail("[{} : FAILED]".format(test))
            errorString = "Error Running valgrind: {}".format(out.returncode)
            raise ValueError(errorString)
    print("\n")
    utils.printGreen(msg="[Memory leak check: PASSED]",
                     module=moduleName)


def runCoverage(moduleName):
    """
    Executes code coverage under 'moduleName' lib unit tests.

    :param moduleName: Lib to be analyzed using gcov and lcov tools.
    """
    currentDir = utils.currentDirPath(moduleName)
    reportFolder = os.path.join(currentDir, "coverage_report")
    includeDir = Path(currentDir)
    moduleCMakeFiles = ""

    if moduleName == "shared_modules/utils":
        moduleCMakeFiles = os.path.join(currentDir, "*/CMakeFiles/*.dir")
        includeDir = includeDir.parent
        paths = glob.glob(moduleCMakeFiles)
    elif moduleName == "syscheckd":
        paths = [root for root, _, _ in os.walk(
            (os.path.join(currentDir, "build"))) if re.search("\.dir$", root)]
    else:
        moduleCMakeFiles = os.path.join(currentDir,
                                        "build/tests/*/CMakeFiles/*.dir")
        paths = glob.glob(moduleCMakeFiles)

    utils.printHeader(moduleName, "coverage")
    folders = ""
    if not os.path.exists(reportFolder):
        os.mkdir(reportFolder)
    for dir in paths:
        folders += "--directory {} ".format(dir)

    coverageCommand = "lcov {} --capture --output-file {}/code_coverage.info \
                       -rc lcov_branch_coverage=0 --exclude=\"*/tests/*\" \
                       --include \"{}/*\" -q".format(folders,
                                                     reportFolder,
                                                     includeDir)

    out = subprocess.run(coverageCommand, stdout=subprocess.PIPE, shell=True)

    if out.returncode == 0:
        utils.printGreen(msg="[lcov info: GENERATED]")
    else:
        print(out.stdout)
        utils.printFail("[lcov: FAILED]")
        errorString = "Error Running lcov: {}".format(out.returncode)
        raise ValueError(errorString)

    genhtmlCommand = "genhtml {}/code_coverage.info --branch-coverage \
                      --output-directory {}".format(reportFolder,
                                                    reportFolder)

    out = subprocess.run(genhtmlCommand, stdout=subprocess.PIPE, shell=True)
    if out.returncode == 0:
        utils.printGreen(msg="[genhtml info: GENERATED]")
        utils.printGreen(msg="Report: {}/index.html".format(reportFolder))
    else:
        print(out.stdout)
        utils.printFail("[genhtml: FAILED]")
        errorString = "Error Running genhtml: {}".format(out.returncode)
        raise ValueError(errorString)
    checkCoverage(out.stdout)


def runCppCheck(moduleName):
    """
    Executes cppcheck static analysis tool under 'moduleName' lib code.

    :param moduleName: Lib to be analyzed using cppcheck static analysis tool.
    """
    utils.printHeader(moduleName, "cppcheck")

    currentDir = utils.currentDirPath(moduleName)
    cppcheckCommand = "cppcheck --force --std=c++14 --quiet \
                       --suppressions-list={}/cppcheckSuppress.txt \
                       {}".format(currentDir, currentDir)

    out = subprocess.run(cppcheckCommand, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0 and not out.stderr:
        utils.printGreen(msg="[Cppcheck: PASSED]")
    else:
        print(out.stderr)
        utils.printFail("[Cppcheck: FAILED]")
        errorString = "Error Running cppcheck: ".format(out.returncode)
        raise ValueError(errorString)


def runTestTool(moduleName, testToolCommand, element, isWindows=False):
    utils.printHeader("TESTTOOL", "testtool")
    utils.printInfo(msg=testToolCommand)
    cwd = os.getcwd()
    currentmoduleNameDir = utils.currentDirPath(moduleName)
    if moduleName == "syscheckd":
        smoke_tests_folder = os.path.join(str.rstrip(
            currentmoduleNameDir, ' '), element['smoke_tests_path'])
        output_folder = os.path.join(
            smoke_tests_folder, element['output_folder'])
    else:
        smoke_tests_folder = os.path.join(currentmoduleNameDir, "smokeTests")
        output_folder = os.path.join(currentmoduleNameDir, "output")

    if element['is_smoke_with_configuration']:
        os.chdir(smoke_tests_folder)
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

    out = subprocess.run(testToolCommand, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)

    os.chdir(cwd)

    if out.returncode == 0 and not out.stderr:
        utils.printGreen(msg="[TestTool: PASSED]")
    elif isWindows and out.returncode == 0:
        utils.printGreen(msg="[TestTool: PASSED]")
    else:
        print(testToolCommand)
        print(out.stderr)
        utils.printFail("[TestTool: FAILED]")
        errorString = "Error Running TestTool: {}".format(out.returncode)
        raise ValueError(errorString)


def runASAN(moduleName, testToolConfig):
    """
    Executes Address Sanitizer dynamic analysis tool under 'moduleName' lib
    code.

    :param moduleName: Lib to be analyzed using ASAN dynamic analysis tool.
    """
    utils.printHeader(moduleName, "asan")
    build_tools.cleanInternals()
    build_tools.makeTarget("agent", False, True)
    build_tools.cleanFolder(str(moduleName), "build")
    build_tools.configureCMake(str(moduleName), True, False, True)
    build_tools.makeLib(str(moduleName))
    module = testToolConfig[moduleName]
    if moduleName == "syscheckd":
        path = module[0]['smoke_tests_path']
    else:
        path = "smokeTests"
    build_tools.cleanFolder(moduleName, os.path.join(path, "output"))

    for element in module:
        path = os.path.join(utils.currentDirPathBuild(moduleName),
                            "bin", element['test_tool_name'])
        args = ' '.join(element['args'])
        testToolCommand = "{} {}".format(path, args)
        runTestTool(str(moduleName), testToolCommand, element)

    utils.printGreen(msg="[ASAN: PASSED]")


def runScanBuild(targetName):
    """
    Executes scan-build for 'targetName'.
    :param targetName: Target to be analyzed using scan-build analysis tool.
    """
    utils.printHeader(targetName, "scanbuild")
    build_tools.cleanAll()
    build_tools.cleanExternals()
    if targetName == "winagent":
        build_tools.makeDeps(targetName, True)
        build_tools.makeTarget("winagent", False, True)
        build_tools.cleanInternals()
        scanBuildCommand = "scan-build-10 --status-bugs \
                            --use-cc=/usr/bin/i686-w64-mingw32-gcc \
                            --use-c++=/usr/bin/i686-w64-mingw32-g++-posix \
                            --analyzer-target=i686-w64-mingw32 \
                            --force-analyze-debug-code \
                            make TARGET=winagent DEBUG=1 -j4"
    else:
        build_tools.makeDeps(targetName, False)
        scanBuildCommand = "scan-build-10 --status-bugs \
                            --force-analyze-debug-code \
                            --exclude external/ make TARGET={} \
                            DEBUG=1 -j4".format(targetName)

    out = subprocess.run(scanBuildCommand, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)

    if out.returncode != 0:
        utils.printFail("[ScanBuild: FAILED]")
        print(scanBuildCommand)
        if out.returncode == 1:
            print(out.stdout)
        else:
            print(out.stderr)
        utils.printFail("[SCANBUILD: FAILED]")
        errorString = "Error Running Scan-build: ".format(out.returncode)
        raise ValueError(errorString)

    utils.printGreen(msg="[SCANBUILD: PASSED]",
                     module=targetName)


def runAStyleCheck(moduleName):
    """
    Executes AStyle coding style analysis tool under 'moduleName' lib code
    failing when one or more files need to be modified.

    :param moduleName: Lib to be analyzed using AStyle coding style
    analysis tool.
    """
    foldersToScan = utils.getFoldersToAStyle(moduleName)
    astyleCommand = "astyle --options=ci/input/astyle.config --dry-run \
                    {}".format(foldersToScan)
    out = subprocess.run(astyleCommand, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)

    if out.returncode == 0 and not out.stderr:
        stdoutString = str(out.stdout)

        if (stdoutString.find("Formatted") != -1):
            utils.printFail("One or more files do not follow the Coding \
                            Style convention.")
            utils.printFail("Execute astyle --options=ci/input/astyle.config \
                            \"{}/*.h\" \"{}/*.cpp\" for further \
                            information.".format(moduleName, moduleName))

            utils.printFail("[AStyle: FAILED]")
            raise ValueError("Code is not complaint with the expected \
                              guidelines")
        else:
            utils.printGreen(msg="[AStyle Check: PASSED]")
    else:
        print(out.stderr)
        utils.printFail("[AStyle Check: FAILED]")
        errorString = "Error Running AStyle: ".format(out.returncode)
        raise ValueError(errorString)


def runAStyleFormat(moduleName):
    """
    Executes AStyle coding style analysis tool under 'moduleName'
    lib code formatting all needed files.

    :param moduleName: Lib to be analyzed using AStyle
    coding style analysis tool.
    """
    foldersToScan = utils.getFoldersToAStyle(moduleName)
    astyleCommand = "astyle --options=ci/input/astyle.config {}"\
                    .format(foldersToScan)
    out = subprocess.run(astyleCommand, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)

    if out.returncode == 0 and not out.stderr:
        utils.printGreen(msg="[AStyle Format: PASSED]")
    else:
        print(out.stderr)
        utils.printFail("[AStyle Format: FAILED]")
        errorString = "Error Running AStyle Format: {}"\
                      .format(out.returncode)
        raise ValueError(errorString)


def runTestToolForWindows(moduleName, testToolConfig):
    utils.printHeader(moduleName, "wintests")
    build_tools.cleanAll()
    build_tools.cleanExternals()
    build_tools.makeDeps("winagent", True)
    build_tools.makeTarget("winagent", False, True)
    winModuleName = "win" + moduleName
    module = testToolConfig[winModuleName]
    rootPath = os.path.join(utils.currentDirPathBuild(moduleName), "bin")
    if moduleName == "syscheckd":
        libgcc = utils.find("libgcc_s_sjlj-1.dll", utils.rootPath())
        rsync = utils.find("rsync.dll", utils.rootPath())
        dbsync = utils.find("dbsync.dll", utils.rootPath())
        shutil.copyfile(libgcc, os.path.join(rootPath, "libgcc_s_sjlj-1.dll"))
        shutil.copyfile(rsync, os.path.join(rootPath, "rsync.dll"))
        shutil.copyfile(dbsync, os.path.join(rootPath, "dbsync.dll"))

    for element in module:
        path = os.path.join(rootPath, element['test_tool_name'])
        args = " ".join(element['args'])
        testToolCommand = "WINEPATH=\"/usr/i686-w64-mingw32/lib;{}\" \
                           WINEARCH=win64 /usr/bin/wine {}.exe {}"\
                           .format(utils.rootPath(), path, args)
        runTestTool(str(moduleName), testToolCommand, element, True)

    utils.printGreen("[TEST TOOL for Windows: PASSED]")


def runReadyToReview(moduleName, clean=False):
    """
    Executes all needed checks under the 'moduleName' lib.

    :param moduleName: Lib to be built and analyzed.
    """

    utils.printHeader(moduleName, "rtr")
    runCppCheck(str(moduleName))
    build_tools.cleanFolder(str(moduleName), "build")
    build_tools. configureCMake(str(moduleName), True, (False, True)[
                                str(moduleName) != 'shared_modules/utils'],
                                False)
    build_tools.makeLib(str(moduleName))
    runTests(str(moduleName))
    runValgrind(str(moduleName))
    runCoverage(str(moduleName))
    runAStyleCheck(str(moduleName))
    try:
        with open("{}/input/testtoolconfig.json".format(CURRENT_DIR), "r")\
                as read_file:
            SmokeTestConfig = json.load(read_file)
    except IOError as e:
        raise e
    if str(moduleName) != "shared_modules/utils":
        runASAN(moduleName, SmokeTestConfig)
    if str(moduleName) == "syscheckd":
        runTestToolForWindows(moduleName, SmokeTestConfig)

    if clean:
        utils.deleteLogs(moduleName)

    utils.printGreen(msg="[RTR: PASSED]",
                     module=moduleName)
