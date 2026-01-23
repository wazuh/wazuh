"""
Copyright (C) 2015, Wazuh Inc.
March 28, 2022.

This program is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public
License (version 2) as published by the FSF - Free Software
Foundation.
"""

import glob
import os
import re
import shutil
import subprocess
from pathlib import Path
from ci import utils
from ci import build_tools


def checkCoverage(output):
    """
    Check the coverage for a library being analyzed.

    Args:
        - output(str): Message to be shown in the stdout.

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception when fails for some reason.
    """
    reLines = re.search(r"lines.*: *([\d.]+)%", str(output))
    reFunctions = re.search(r"functions.*: *([\d.]+)%", str(output))

    if reLines:
        linesCoverage = reLines.group(1)
    else:
        linesCoverage = "0.0"

    if reFunctions:
        functionsCoverage = reFunctions.group(1)
    else:
        functionsCoverage = "0.0"
    if float(linesCoverage) >= 90.0:
        utils.printGreen(msg="[Lines Coverage {}%: PASSED]"
                         .format(linesCoverage))
    else:
        utils.printFail(msg="[Lines Coverage {}%: LOW]".format(linesCoverage))
        errorString = "Low lines coverage: {}".format(linesCoverage)
        raise ValueError(errorString)
    if float(functionsCoverage) >= 90.0:
        utils.printGreen(msg="[Functions Coverage {}%: PASSED]"
                         .format(functionsCoverage))
    else:
        utils.printFail(msg="[Functions Coverage {functionsCoverage}%: LOW]")
        errorString = "Low functions coverage: {}".format(functionsCoverage)
        raise ValueError(errorString)


def runASAN(moduleName, testToolConfig):
    """
    Execute Address Sanitizer dynamic analysis tool using the test tool
    defined for a library.

    Args:
        - moduleName(str): Library to be analyzed using ASAN dynamic analysis
                           tool.
        - testToolConfig(map): Test tool parameters.

    Returns:
        - None

    Raises:
        - None
    """
    utils.printHeader(moduleName,
                      headerKey="asan")

    # Centralized build: rebuild test tools with ASAN
    build_tools.cleanInternals()
    build_tools.makeTarget(targetName="agent",
                           tests=False,
                           debug=True,
                           fsanitize=True)

    module = testToolConfig[moduleName]
    if moduleName == "syscheckd":
        path = module[0]['smoke_tests_path']
    else:
        path = "smokeTests"
    build_tools.cleanFolder(moduleName=moduleName,
                            additionalFolder=os.path.join(path,
                                                          "output"))
    for element in module:
        # Centralized build: test tools are in build/bin
        path = os.path.join(utils.rootPath(), "build", "bin", element['test_tool_name'])
        args = ' '.join(element['args'])
        testToolCommand = "{} {}".format(path, args)
        runTestTool(moduleName=moduleName,
                    testToolCommand=testToolCommand,
                    element=element)

    utils.printGreen(msg="[ASAN: PASSED]")


def runAStyleCheck(moduleName):
    """
    Execute AStyle coding style analysis for the library
    code failing when one or more files need to be modified.

    Args:
        - moduleName: Library to be analyzed using AStyle coding style
                      analysis tool.
    Returns:
        - None

    Raises:
        - ValueError: Raises an exception when fails for some reason.
    """
    foldersToScan = utils.getFoldersToAStyle(moduleName=moduleName)
    astyleCommand = "astyle --options=ci/input/astyle.config --dry-run \
                    {}".format(foldersToScan)
    out = subprocess.run(astyleCommand,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False)
    if out.returncode == 0 and not out.stderr:
        stdoutString = str(out.stdout)

        if stdoutString.find("Formatted") != -1:
            utils.printFail(msg="One or more files do not follow the Coding \
                                 Style convention.")
            utils.printFail(msg="Execute astyle \
                                 --options=ci/input/astyle.config \
                                 \"{0}/*.h\" \"{0}/*.hpp\" \"{0}/*.cpp\" \
                                 for further information.".format(moduleName))

            utils.printFail(msg="[AStyle: FAILED]")
            raise ValueError("Code is not complaint with the expected \
                              guidelines")
    else:
        print(out.stderr.decode('utf-8','replace'))
        utils.printFail(msg="[AStyle Check: FAILED]")
        errorString = "Error Running AStyle: {}".format(out.returncode)
        raise ValueError(errorString)
    utils.printGreen(msg="[AStyle Check: PASSED]")


def runAStyleFormat(moduleName):
    """
    Execute AStyle coding style analysis tool for the library code
    formatting all needed files.

    Args:
        - moduleName: Library to be formated using AStyle coding style
                      analysis tool.

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception when fails for some reason.
    """
    foldersToScan = utils.getFoldersToAStyle(moduleName=moduleName)
    astyleCommand = "astyle --options=ci/input/astyle.config {}"\
                    .format(foldersToScan)
    out = subprocess.run(astyleCommand,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False)
    if out.returncode == 0 and not out.stderr:
        utils.printGreen(msg="[AStyle Format: PASSED]")
    else:
        print(out.stderr.decode('utf-8','replace'))
        utils.printFail(msg="[AStyle Format: FAILED]")
        errorString = "Error Running AStyle Format: {}"\
                      .format(out.returncode)
        raise ValueError(errorString)


def runCoverage(moduleName):
    """
    Execute code coverage for a library unit tests.

    Args:
        - moduleName: Library to be analyzed using gcov and lcov tools.

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception when fails for some reason.
    """
    currentDir = utils.moduleDirPath(moduleName=moduleName)
    reportFolder = os.path.join(currentDir, "coverage_report")

    includeDir = Path(currentDir)

    # Centralized build: find all .dir directories with coverage files under build/moduleName/
    centralizedBuildDir = os.path.join(utils.rootPath(), "build", moduleName)
    paths = [root for root, _, _ in os.walk(centralizedBuildDir) if root.endswith('.dir')]
    utils.printHeader(moduleName=moduleName,
                      headerKey="coverage")
    folders = ""
    if not os.path.exists(reportFolder):
        os.mkdir(reportFolder)
    for aux in paths:
        folders += "--directory {} ".format(aux)

    # Build exclusion patterns based on module
    excludePatterns = ["*/tests/*"]
    if moduleName == "shared_modules/sync_protocol":
        excludePatterns.extend(["*inventorySync_generated*"])

    excludeArgs = " ".join('--exclude="{}"'.format(pattern) for pattern in excludePatterns)

    coverageCommand = "lcov {} --capture --output-file {}/code_coverage.info \
                       -rc lcov_branch_coverage=0 {} \
                       --include \"{}/*\" -q".format(folders,
                                                     reportFolder,
                                                     excludeArgs,
                                                     includeDir)
    out = subprocess.run(coverageCommand,
                         stdout=subprocess.PIPE,
                         shell=True,
                         check=False)
    if out.returncode == 0:
        utils.printGreen(msg="[lcov info: GENERATED]")
    else:
        print(out.stdout.decode('utf-8','replace'))
        utils.printFail(msg="[lcov: FAILED]")
        errorString = "Error Running lcov: {}".format(out.returncode)
        raise ValueError(errorString)
    genhtmlCommand = "genhtml {0}/code_coverage.info --branch-coverage \
                      --output-directory {0}".format(reportFolder)
    out = subprocess.run(genhtmlCommand,
                         stdout=subprocess.PIPE,
                         shell=True,
                         check=False)
    if out.returncode == 0:
        utils.printGreen(msg="[genhtml info: GENERATED]")
        utils.printGreen(msg="Report: {}/index.html".format(reportFolder))
    else:
        print(out.stdout.decode('utf-8','replace'))
        utils.printFail(msg="[genhtml: FAILED]")
        errorString = "Error Running genhtml: {}".format(out.returncode)
        raise ValueError(errorString)
    checkCoverage(out.stdout)


def runCppCheck(moduleName):
    """
    Execute cppcheck static analysis in the library code.

    Args:
        - moduleName: Library to be analyzed using cppcheck static analysis tool.

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception when fails for some reason.
    """
    utils.printHeader(moduleName=moduleName,
                      headerKey="cppcheck")

    currentDir = utils.moduleDirPath(moduleName)
    cppcheckCommand = "cppcheck --force --std=c++17 --quiet {}".format(currentDir)

    out = subprocess.run(cppcheckCommand,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False)
    if out.returncode == 0 and not out.stderr:
        utils.printGreen(msg="[Cppcheck: PASSED]")
    else:
        print(out.stdout.decode('utf-8','replace'))
        print(out.stderr.decode('utf-8','replace'))
        utils.printFail(msg="[Cppcheck: FAILED]")
        errorString = "Error Running cppcheck: {}".format(out.returncode)
        raise ValueError(errorString)


def runReadyToReview(moduleName, clean=False, target="agent"):
    """
    Executes all needed checks for a library in order to create a PR.

    Args:
        - moduleName: Library to be built and analyzed.
        - clean: Delete logs.
        - target: Build type. <agent, winagent, server>

    Returns:
        - None
    """
    utils.printHeader(moduleName=moduleName,
                      headerKey="rtr")

    # We first run the fastest tests
    runCppCheck(moduleName=moduleName)
    runAStyleCheck(moduleName=moduleName)

    # Making a full clean, downloading external dependencies and
    # building the corresponding target with tests flag enabled
    build_tools.cleanAll()
    build_tools.makeDeps(targetName=target,
                         srcOnly=False)
    build_tools.makeTarget(targetName=target,
                           tests=True,
                           debug=True,
                           fsanitize=(target != "winagent"))

    # Running UTs and coverage
    runTests(moduleName=moduleName)
    # The coverage for these modules in 'winagent' target will be added in #17008
    if (target == 'winagent' and moduleName == 'data_provider') or \
       (target == 'winagent' and moduleName == 'shared_modules/file_helper'):
        utils.printInfo(msg="Skipping coverage for {} in {} target".format(
                        moduleName, target))
    else:
        runCoverage(moduleName=moduleName)

    # We run valgrind for all targets except Windows
    # The memory analysis for Wine will be enabled in #17018
    if target != "winagent":
        runValgrind(moduleName=moduleName)

    # For the following tests we don't require the tests flag
    build_tools.cleanInternals()
    if target == "winagent":
        build_tools.cleanWindows()
    build_tools.makeTarget(targetName=target,
                           tests=False,
                           debug=True)

    configPath = os.path.join(utils.currentPath(),
                              "input/test_tool_config.json")
    smokeTestConfig = utils.readJSONFile(jsonFilePath=configPath)
    # We run the test tool for syscheckd in Windows
    if moduleName == 'syscheckd' and target == 'winagent':
        runTestToolForWindows(moduleName=moduleName,
                              testToolConfig=smokeTestConfig)
        runTestToolCheck(moduleName=moduleName)

    # The ASAN check is in the end. It builds again the module but with the ASAN flag
    # and runs the test tool.
    # Running this type of check in Windows will be analyzed in #17019
    if target != "winagent" and moduleName != "shared_modules/agent_metadata" and moduleName != "shared_modules/file_helper" and moduleName != "wazuh_modules/agent_info" and moduleName != "wazuh_modules/sca":
        runASAN(moduleName=moduleName,
                testToolConfig=smokeTestConfig)
    if clean:
        os.chdir(os.path.join(utils.rootPath(), moduleName))
        utils.deleteLogs(moduleName=moduleName)
    utils.printGreen(msg="[RTR: PASSED]",
                     module=moduleName)


def runScanBuild(targetName):
    """
    Execute scan-build for a defined target.

    Args:
        - targetName: Target to be analyzed using scan-build analysis tool.
                      <agent, server, winagent>

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception when fails for some reason.
    """
    utils.printHeader(moduleName=targetName,
                      headerKey="scanbuild")
    build_tools.cleanAll()
    build_tools.cleanExternals()
    build_tools.makeDeps(targetName=targetName,
                         srcOnly=False)
    build_tools.makeTarget(targetName=targetName,
                           tests=False,
                           debug=True)
    # We don't call cleanWindows() for scan-build.
    build_tools.cleanInternals()
    if targetName == "winagent":
        scanBuildCommand = "scan-build --status-bugs \
                            --use-cc=/usr/bin/i686-w64-mingw32-gcc \
                            --use-c++=/usr/bin/i686-w64-mingw32-g++-posix \
                            --analyzer-target=i686-w64-mingw32 \
                            --force-analyze-debug-code \
                            make TARGET=winagent DEBUG=1 -j4"
    else:
        scanBuildCommand = "scan-build --status-bugs \
                            --force-analyze-debug-code \
                            --exclude external/ make TARGET={} \
                            DEBUG=1 -j4".format(targetName)
    out = subprocess.run(scanBuildCommand,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False)
    if out.returncode != 0:
        utils.printFail(msg="[ScanBuild: FAILED]")
        print(scanBuildCommand)
        if out.returncode == 1:
            print(out.stdout.decode('utf-8','replace'))
        else:
            print(out.stderr.decode('utf-8','replace'))
        utils.printFail(msg="[SCANBUILD: FAILED]")
        errorString = "Error Running Scan-build: {}".format(out.returncode)
        raise ValueError(errorString)

    utils.printGreen(msg="[SCANBUILD: PASSED]",
                     module=targetName)


def runTestTool(moduleName, testToolCommand, element):
    """
    Execute test tool for a module with a configuration passed by parameters.

    Args:
        - moduleName(str): Library to be built and analyzed.
        - testToolCommand(str): Literal command to be executed.
        - element(map): Test tool configuration.

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception when fails for some reason.
    """
    utils.printHeader(moduleName="TESTTOOL",
                      headerKey="testtool")
    utils.printInfo(msg=testToolCommand)
    cwd = os.getcwd()
    currentmoduleNameDir = utils.moduleDirPath(moduleName=moduleName)
    if moduleName == "syscheckd":
        smokeTestsFolder = os.path.join(str.rstrip(currentmoduleNameDir,
                                                   ' '),
                                        element['smoke_tests_path'])
        outputFolder = os.path.join(smokeTestsFolder,
                                    element['output_folder'])
    else:
        smokeTestsFolder = os.path.join(currentmoduleNameDir,
                                        "smokeTests")
        outputFolder = os.path.join(currentmoduleNameDir,
                                    "output")
    if element['is_smoke_with_configuration']:
        os.chdir(smokeTestsFolder)
        if not os.path.exists(outputFolder):
            os.makedirs(outputFolder)
    else:
        os.chdir(currentmoduleNameDir)
    out = subprocess.run(testToolCommand,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False)
    os.chdir(cwd)
    if out.returncode != 0:
        print(testToolCommand)
        print(out.stderr.decode('utf-8','replace'))
        utils.printFail(msg="[TestTool: FAILED]")
        errorString = "Error Running TestTool: {}".format(out.returncode)
        raise ValueError(errorString)


def runTestToolForWindows(moduleName, testToolConfig):
    """
    Execute test tool for a module with a configuration passed by parameters
    for Windows OS.

    Args:
        - moduleName(str): Library to be built and analyzed.
        - testToolConfig(map): Test tool configuration.

    Returns:
        - None

    Raises:
        - None
    """
    utils.printHeader(moduleName, headerKey="wintesttool")
    winModuleName = "win" + moduleName
    module = testToolConfig[winModuleName]

    # Centralized build directory
    rootPath = os.path.join(utils.rootPath(), "build", "bin")

    libgcc = utils.findFile(name="libgcc_s_dw2-1.dll",
                            path=utils.rootPath())
    dbsync = utils.findFile(name="dbsync.dll",
                            path=utils.rootPath())
    agent_sync_protocol = utils.findFile(name="libagent_sync_protocol.dll",
                                        path=utils.rootPath())
    schema_validator = utils.findFile(name="schema_validator.dll",
                                      path=utils.rootPath())
    agent_metadata = utils.findFile(name="libagent_metadata.dll",
                                    path=utils.rootPath())
    stdcpp = utils.findFile(name="libstdc++-6.dll",
                            path=utils.rootPath())
    shutil.copyfile(libgcc,
                    os.path.join(rootPath, "libgcc_s_dw2-1.dll"))
    shutil.copyfile(dbsync,
                    os.path.join(rootPath, "dbsync.dll"))
    shutil.copyfile(agent_sync_protocol,
                    os.path.join(rootPath, "libagent_sync_protocol.dll"))
    shutil.copyfile(schema_validator,
                    os.path.join(rootPath, "schema_validator.dll"))
    shutil.copyfile(agent_metadata,
                    os.path.join(rootPath, "libagent_metadata.dll"))
    shutil.copyfile(stdcpp,
                    os.path.join(rootPath, "libstdc++-6.dll"))

    for element in module:
        path = os.path.join(rootPath, element['test_tool_name'])
        args = " ".join(element['args'])
        testToolCommand = "WINEPATH=\"/usr/i686-w64-mingw32/lib;{}\" \
                           WINEARCH=win64 /usr/bin/wine {}.exe {}"\
                           .format(utils.rootPath(), path, args)
        runTestTool(moduleName=moduleName,
                    testToolCommand=testToolCommand,
                    element=element)

    utils.printGreen(msg="[TEST TOOL for Windows: PASSED]")


def safe_copy(src, dst):
    """Copy file if src exists and is different from dst."""
    if src and os.path.abspath(src) != os.path.abspath(dst):
        shutil.copyfile(src, dst)


def runTests(moduleName):
    """
    Execute library tests.

    Args:
        - moduleName: Library representing the tests to be executed.

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception when fails for some reason.
    """
    utils.printHeader(moduleName=moduleName,
                      headerKey="tests")
    tests = []
    reg = re.compile(r".*(?:unit_test|integration_test|interface_test|_test|_tests)(?:\.exe)?$")

    # Use centralized build directory
    currentDir = os.path.join(utils.rootPath(), "build", "bin")
    # Extract module base name for filtering tests
    # e.g., "wazuh_modules/agent_info" -> "agent_info"
    moduleBaseName = os.path.basename(moduleName)

    objects = os.scandir(currentDir)
    for entry in objects:
        if entry.is_file() and bool(re.match(reg, entry.name)):
            # Filter by module name prefix
            if not entry.name.startswith(moduleBaseName):
                continue
            tests.append(entry.name)

    cwd = os.getcwd()
    if len(tests) > 0:
        os.chdir(currentDir)
        for test in tests:
            path = os.path.join(currentDir, test)
            if ".exe" in test:
                # Don't copy DLLs!! Just add the correct paths
                # For centralized build, all DLLs are in build/bin
                centralizedBinDir = os.path.join(utils.rootPath(), "build", "bin")
                dll_dirs = [
                    "/usr/i686-w64-mingw32/bin",
                    "/usr/i686-w64-mingw32/lib",
                    utils.currentPath(),
                    currentDir,  # already chdir'ed to this later
                    centralizedBinDir,
                ]

                # Add GCC runtime DLL paths - prioritize -posix variant
                gcc_root = "/usr/lib/gcc/i686-w64-mingw32"
                if os.path.isdir(gcc_root):
                    # First add -posix variants (higher priority)
                    for sub in sorted(os.listdir(gcc_root), reverse=True):
                        if "-posix" in sub:
                            p = os.path.join(gcc_root, sub)
                            if os.path.isdir(p):
                                dll_dirs.append(p)
                    # Then add others as fallback
                    for sub in sorted(os.listdir(gcc_root), reverse=True):
                        if "-posix" not in sub:
                            p = os.path.join(gcc_root, sub)
                            if os.path.isdir(p):
                                dll_dirs.append(p)

                for _name in ("libstdc++-6.dll", "libgcc_s_dw2-1.dll", "libwinpthread-1.dll",
                              "dbsync.dll", "sysinfo.dll", "libwazuhext.dll", "libagent_sync_protocol.dll",
                              "libagent_metadata.dll", "schema_validator.dll"):
                    try:
                        _p = utils.findFile(name=_name, path=utils.rootPath())
                        if _p:
                            dll_dirs.append(os.path.dirname(_p))
                    except Exception:
                        pass

                # De-dup + keep only existing dirs
                uniq_dirs = []
                seen = set()
                for d in (os.fspath(x) for x in dll_dirs if x and os.path.isdir(os.fspath(x))):
                    if d not in seen:
                        seen.add(d)
                        uniq_dirs.append(d)

                # Use WINEPATH instead of Windows PATH for proper DLL search order
                winepath_str = ";".join(uniq_dirs)

                command = (
                    f'WINEPATH="{winepath_str}" '
                    f'WINEARCH=win64 '
                    'wine reg add "HKCU\\Software\\Wine\\WineDbg" /v ShowCrashDialog /t REG_DWORD /d 0 /f & '
                    f'WINEPATH="{winepath_str}" wine {os.path.basename(path)}'
                )
            else:
                command = path
            out = subprocess.run(command,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 shell=True,
                                 check=False)
            if out.returncode == 0:
                utils.printGreen(msg="[{}: PASSED]".format(test))
            else:
                print(out.stdout.decode('utf-8','replace'))
                print(out.stderr.decode('utf-8','replace'))
                utils.printFail(msg="[{}: FAILED]".format(test))
                errorString = "Error Running test: {}".format(out.returncode)
                raise ValueError(errorString)

        utils.printGreen(msg="[All tests: PASSED]",
                         module=moduleName)
    else:
        errorString = "Error Running tests"
        raise ValueError(errorString)

    os.chdir(cwd)


def runTestToolCheck(moduleName):
    """
    Results are taken in JSON format after running the test tool
    and validated using pytest.

    Args:
        - moduleName: Library to analyze test tool results using pytest tool.

    Returns:
        - None

    Raises:
        - CalledProcessError: Raises an exception when fails some test.
    """
    path = os.path.join(utils.currentPath(),
                        "tests")
    pathResult = os.path.join(path,
                              "results")
    if not os.path.exists(pathResult):
        os.makedirs(pathResult)

    cmd = "pytest -svx {} --moduleName={} \
           --html=ci/tests/results/results.html \
           --capture=tee-sys"
    try:
        out = subprocess.run(cmd.format(path, moduleName),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=True,
                             check=False)
        if out.returncode == 0:
            utils.printGreen(msg="[TestTool check: PASSED]")
    except Exception as e:
        errorString = "Error checking test tool results. See more details {}"\
                      .format(os.path.join(pathResult, "results.html"))
        utils.printFail(msg="[TestTool check: FAILED]")
        print(errorString)
        raise e


def runValgrind(moduleName):
    """
    Execute all tests with valgrind tool in order to check memory leaks
    in the library code.

    Args:
        - moduleName: Library to be analyzed using valgrind tool.

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception when fails for some reason.
    """
    utils.printHeader(moduleName=moduleName,
                      headerKey="valgrind")

    # Rebuild tests without sanitizers for valgrind compatibility
    build_tools.cleanInternals()
    build_tools.makeTarget(targetName="agent",
                           tests=True,
                           debug=True,
                           fsanitize=False,
                           valgrind=True)

    tests = []
    reg = re.compile(r".*(?:unit_test|integration_test|interface_test|_test|_tests)(?:\.exe)?$")

    # Centralized build: tests are in build/bin/
    currentDir = os.path.join(utils.rootPath(), "build", "bin")
    moduleBaseName = os.path.basename(moduleName)

    objects = os.scandir(currentDir)
    for entry in objects:
        if entry.is_file() and bool(re.match(reg, entry.name)):
            # Filter by module name prefix
            if not entry.name.startswith(moduleBaseName):
                continue
            tests.append(entry.name)
    valgrindCommand = "valgrind --leak-check=full --show-leak-kinds=all \
                       -q --error-exitcode=1 {}".format("./")
    oldPath = os.getcwd()
    os.chdir(currentDir)
    for test in tests:
        out = subprocess.run(os.path.join(valgrindCommand, test),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=True,
                             check=False)
        if out.returncode == 0:
            utils.printGreen(msg="[{} : PASSED]".format(test))
        else:
            print(out.stdout.decode('utf-8', 'replace'))
            print(out.stderr.decode('utf-8', 'replace'))
            utils.printFail(msg="[{} : FAILED]".format(test))
            errorString = "Error Running valgrind: {}".format(out.returncode)
            raise ValueError(errorString)
    os.chdir(oldPath)
    utils.printGreen(msg="[Memory leak check: PASSED]",
                     module=moduleName)
