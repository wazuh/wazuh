"""
Copyright (C) 2015, Wazuh Inc.
March 28, 2022.

This program is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public
License (version 2) as published by the FSF - Free Software
Foundation.
"""

import os
import subprocess
from ci import utils


# Constant values
DELETE_FOLDER_DIC = {
    'wazuh_modules/syscollector':   ['build', 'smokeTests/output'],
    'shared_modules/dbsync':        ['build', 'smokeTests/output'],
    'shared_modules/rsync':         ['build', 'smokeTests/output'],
    'shared_modules/file_helper':   ['build'],
    'data_provider':                ['build', 'smokeTests/output'],
    'syscheckd':                    ['build', 'src/db/smokeTests/output',
                                     'coverage_report'],
}


def cleanAll():
    """
    Execute the command 'make clean' in the operating system.

    Args:
        - None

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception.
    """
    out = subprocess.run("make clean",
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False,
                         text=False)
    if out.returncode == 0:
        utils.printGreen(msg="[CleanAll: PASSED]")
    else:
        print("make clean")
        print(out.stderr.decode('utf-8','replace'))
        utils.printFail(msg="[CleanAll: FAILED]")
        errorString = "Error Running CleanAll: {}".format(out.returncode)
        raise ValueError(errorString)


def cleanExternals():
    """
    Delete the contents of the external folder.

    Args:
        - None

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception.
    """
    out = subprocess.run("rm -rf ./external/*",
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False)
    if out.returncode == 0 and not out.stderr:
        utils.printGreen("[CleanExternals: PASSED]")
    else:
        print("rm -rf ./external/*")
        print(out.stderr.decode('utf-8','replace'))
        utils.printFail(msg="[CleanExternals: FAILED]")
        errorString = "Error Running CleanExternals: {}".format(out.returncode)
        raise ValueError(errorString)


def cleanFolder(moduleName, additionalFolder, folderName=""):
    """
    Delete a specific folder inside some module.

    Args:
        - moduleName(str): Main folder name.
        - additionalFolder(str): Subfolder inside library folder to delete.
        - folderName(str): Name in order to log a folder to delete.

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception.

    Example:
        cleanFolder("syscheckd", "build", "syscheckd")
    """
    currentDir = utils.moduleDirPath(moduleName)
    cleanFolderCommand = "rm -rf {}".format(os.path.join(currentDir,
                                                         additionalFolder))
    if DELETE_FOLDER_DIC[moduleName].count(additionalFolder) > 0:
        out = subprocess.run(cleanFolderCommand,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=True,
                             check=False)
        if out.returncode == 0 and not out.stderr:
            utils.printGreen(msg="[Cleanfolder {}: PASSED]".format(folderName))
        else:
            print(cleanFolderCommand)
            print(out.stderr.decode('utf-8','replace'))
            utils.printFail(msg="[Cleanfolder {}: FAILED]".format(folderName))
            errorString = "Error Running Cleanfolder: {}".format(
                out.returncode)
            raise ValueError(errorString)
    else:
        utils.printFail(msg="[Cleanfolder {}: FAILED]".format(folderName))
        errorString = "Error Running Cleanfolder: additional folder\
                       not exist in delete folder dictionary."
        raise ValueError(errorString)


def cleanInternals():
    """
    Execute the command 'make clean-internals' in the operating system.

    Args:
        - None

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception.
    """
    os.chdir(utils.rootPath())
    out = subprocess.run("make clean-internals",
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False,
                         text=False)
    if out.returncode == 0:
        utils.printGreen(msg="[CleanInternals: PASSED]")
    else:
        print("make clean-internals")
        print(out.stderr.decode('utf-8','replace'))
        utils.printFail(msg="[CleanInternals: FAILED]")
        errorString = "Error Running CleanInternals: {}".format(out.returncode)
        raise ValueError(errorString)

def cleanWindows():
    """
    Execute the command 'make clean-windows' in the operating system.

    Args:
        - None

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception.
    """
    os.chdir(utils.rootPath())
    out = subprocess.run("make clean-windows",
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False,
                         text=False)
    if out.returncode == 0:
        utils.printGreen(msg="[CleanWindows: PASSED]")
    else:
        print("make clean-windows")
        print(out.stderr.decode('utf-8','replace'))
        utils.printFail(msg="[CleanWindows: FAILED]")
        errorString = "Error Running CleanWindows: {}".format(out.returncode)
        raise ValueError(errorString)

def cleanLib(moduleName):
    """
    Clean the files generated in some module when it is built.

    Args:
        - moduleName(str): Library name to be clean.

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception.

    Example:
        cleanFolder("data_provider")
    """
    currentDir = utils.moduleDirPathBuild(moduleName)
    out = subprocess.run("make -C {} clean".format(currentDir),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False)
    if out.returncode == 0:
        utils.printGreen(msg="[CleanLib: PASSED]")
    else:
        print("make -C {} clean".format(moduleName))
        print(out.stderr.decode('utf-8','replace'))
        utils.printFail(msg="[CleanLib: FAILED]")
        errorString = "Error Running CleanLib: {}".format(out.returncode)
        raise ValueError(errorString)


def configureCMake(moduleName, debugMode, testMode, withAsan):
    """
    Configure cmake command with specific configuration based on
    the parameters passed to the function.

    Args:
        - moduleName(str): Library name to be build.
        - debugMode(bool): Build library with debug flag.
        - testMode(bool): Build tests for the library.
        - withASAN(bool): Build with address sanitizer.

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception.

    Example:
        configureCMake("data_provider",
                        debugMode=True,
                        testMode=False,
                        withAsan=False)
    """
    utils.printSubHeader(moduleName=moduleName,
                         headerKey="configurecmake")
    os.chdir(utils.moduleDirPath(moduleName=moduleName))
    currentPathDir = utils.moduleDirPathBuild(moduleName=moduleName)
    if not os.path.exists(currentPathDir):
        os.mkdir(currentPathDir)
    configureCMakeCommand = "cmake -S {} -B {}"\
                            .format(".", currentPathDir)
    if debugMode:
        configureCMakeCommand += " -DCMAKE_BUILD_TYPE=Debug"

    if testMode:
        configureCMakeCommand += " -DUNIT_TEST=1"

    if withAsan:
        configureCMakeCommand += " -DFSANITIZE=1"

    out = subprocess.run(configureCMakeCommand,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False)
    os.chdir(utils.rootPath())
    if out.returncode == 0 and not out.stderr:
        utils.printGreen(msg="[ConfigureCMake: PASSED]")
    else:
        print(configureCMakeCommand)
        print(out.stderr.decode('utf-8','replace'))
        utils.printFail(msg="[ConfigureCMake: FAILED]")
        errorString = "Error Running ConfigureCMake: {}".format(out.returncode)
        raise ValueError(errorString)


def deleteFolderDic():
    """
    Get a map with configured folders to be deleted.

    Args:
        - None

    Returns:
        - DELETE_FOLDER_DIC(map): Folders to each module to be deleted.

    Raises:
        ValueError: Raises an exception.
    """
    return DELETE_FOLDER_DIC


def makeDeps(targetName, srcOnly):
    """
    Use make command in order to download dependencies and
    after that build them.

    Args:
        - targetName(str): Dependencies type to be build.
                           <agent, server, winagent>
        - srcOnly(bool): Only builds external dependencies.

    Returns:
        None

    Raises:
        - ValueError: Raises an exception.

    Example:
        makeDeps("wazuh_modules/syscollector", srcOnly=True)
    """
    utils.printSubHeader(moduleName=targetName,
                         headerKey="makeDeps")
    makeDepsCommand = "make deps TARGET={} -j{}".format(targetName, utils.getCpuCores())
    if srcOnly:
        makeDepsCommand += " EXTERNAL_SRC_ONLY=yes"
    out = subprocess.run(makeDepsCommand,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False)
    if out.returncode == 0:
        utils.printGreen(msg="[MakeDeps: PASSED]")
    else:
        print(makeDepsCommand)
        print(out.stderr.decode('utf-8','replace'))
        utils.printFail(msg="[MakeDeps: FAILED]")
        errorString = "Error Running MakeDeps: {}".format(out.returncode)
        raise ValueError(errorString)


def makeLib(moduleName):
    """
    Build a library.

    Args:
        - moduleName(str): Library to be built.

    Returns:
        - None

    Raises:
        - ValueError: Raises an exception.

    Example:
        makeLib("syscheckd")
    """
    command = "make -C {} -j{}".format(utils.moduleDirPathBuild(moduleName), utils.getCpuCores())
    utils.printSubHeader(moduleName=moduleName,
                         headerKey="make")

    out = subprocess.run(command,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False)
    if out.returncode != 0:
        print(command)
        print(out.stdout.decode('utf-8','replace'))
        print(out.stderr.decode('utf-8','replace'))
        errorString = "Error compiling library: {}".format(out.returncode)
        raise ValueError(errorString)
    utils.printGreen(msg="[make: PASSED]")


def makeTarget(targetName, tests, debug):
    """
    Build project with flags.

    Args:
        - targetName(str): Build type to be built
                           <agent, server, winagent>.
        - tests(bool): Build all tests.
        - debug(bool): Build with debug binaries.

    Returns:
        None

    Raises:
        ValueError: Raises an exception.

    Example:
        makeTarget("winagent", tests=True, debug=True)
    """
    utils.printSubHeader(moduleName=targetName,
                         headerKey="makeAll")
    makeTargetCommand = "make TARGET={}".format(targetName)
    if tests:
        makeTargetCommand += " TEST=1"
    if debug:
        makeTargetCommand += " DEBUG=1"
    makeTargetCommand += " -j{}".format(utils.getCpuCores())
    out = subprocess.run(makeTargetCommand,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False)
    if out.returncode == 0:
        utils.printGreen(msg="[MakeTarget: PASSED]")
    else:
        print(makeTargetCommand)
        print(out.stderr.decode('utf-8','replace'))
        utils.printFail(msg="[MakeTarget: FAILED]")
        errorString = "Error Running MakeTarget: {}".format(out.returncode)
        raise ValueError(errorString)
