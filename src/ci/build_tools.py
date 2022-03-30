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


DELETE_FOLDER_DIC = {
    'wazuh_modules/syscollector':   ['build', 'smokeTests/output'],
    'shared_modules/dbsync':        ['build', 'smokeTests/output'],
    'shared_modules/rsync':         ['build', 'smokeTests/output'],
    'data_provider':                ['build', 'smokeTests/output'],
    'shared_modules/utils':         ['build'],
    'syscheckd':                    ['build', 'src/db/smokeTests/output',
                                     'coverage_report'],
}


def cleanAll():
    """
    Execute the command 'make clean' in the operating system.

    Args:
        None

    Returns:
        None

    Raises:
        ValueError: Raises an exception.
    """
    out = subprocess.run("make clean", stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True, check=True)
    if out.returncode == 0:
        utils.printGreen("[CleanAll: PASSED]")
    else:
        print("make clean")
        print(out.stderr)
        utils.printFail("[CleanAll: FAILED]")
        errorString = "Error Running CleanAll: {}".format(out.returncode)
        raise ValueError(errorString)


def cleanExternals():
    """
    Delete the contents of the external folder.

    Args:
        None

    Returns:
        None

    Raises:
        ValueError: Raises an exception.
    """
    out = subprocess.run("rm -rf ./external/*", stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True, check=True)
    if out.returncode == 0 and not out.stderr:
        utils.printGreen("[CleanExternals: PASSED]")
    else:
        print("rm -rf ./external/*")
        print(out.stderr)
        utils.printFail("[CleanExternals: FAILED]")
        errorString = "Error Running CleanExternals: {}".format(out.returncode)
        raise ValueError(errorString)


def cleanFolder(moduleName, additionalFolder, folderName=""):
    """
    Delete a specific folder inside some module.

    Args:
        moduleName(str): Main folder name.
        additionalFolder(str): Subfolder inside library folder to delete.
        folderName(str): Name in order to log a folder to delete.

    Returns:
        None

    Raises:
        ValueError: Raises an exception

    Example:
        cleanFolder("syscheckd", "build", "syscheckd")
    """
    currentDir = utils.moduleDirPath(moduleName)
    cleanFolderCommand = "rm -rf {}".format(os.path.join(currentDir,
                                                         additionalFolder))

    if DELETE_FOLDER_DIC[moduleName].count(additionalFolder) > 0:
        out = subprocess.run(cleanFolderCommand, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True, check=True)
        if out.returncode == 0 and not out.stderr:
            utils.printGreen("[Cleanfolder {}: PASSED]".format(folderName))
        else:
            print(cleanFolderCommand)
            print(out.stderr)
            utils.printFail("[Cleanfolder {}: FAILED]".format(folderName))
            errorString = "Error Running Cleanfolder: {}".format(
                out.returncode)
            raise ValueError(errorString)
    else:
        utils.printFail("[Cleanfolder {}: FAILED]".format(folderName))
        errorString = "Error Running Cleanfolder: additional folder\
                       not exist in delete folder dictionary."
        raise ValueError(errorString)


def cleanInternals():
    """
    Execute the command 'make clean-internals' in the operating system.

    Args:
        None

    Returns:
        None

    Raises:
        ValueError: Raises an exception
    """
    out = subprocess.run("make clean-internals", stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True, check=True)
    if out.returncode == 0:
        utils.printGreen("[CleanInternals: PASSED]")
    else:
        print("make clean-internals")
        print(out.stderr)
        utils.printFail("[CleanInternals: FAILED]")
        errorString = "Error Running CleanInternals: {}".format(out.returncode)
        raise ValueError(errorString)


def cleanLib(moduleName):
    """
    Clean the files generated in some module when it is built.

    Args:
        moduleName(str): Library name to be clean.

    Returns:
        None

    Raises:
        ValueError: Raises an exception

    Example:
        cleanFolder("data_provider")
    """
    currentDir = utils.moduleDirPathBuild(moduleName)
    out = subprocess.run("make -C {} clean".format(currentDir),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         shell=True, check=True)
    if out.returncode == 0:
        utils.printGreen("[CleanLib: PASSED]")
    else:
        print("make -C {} clean".format(moduleName))
        print(out.stderr)
        utils.printFail("[CleanLib: FAILED]")
        errorString = "Error Running CleanLib: {}".format(out.returncode)
        raise ValueError(errorString)


def configureCMake(moduleName, debugMode, testMode, withAsan):
    """
    Clean the files generated in some module when it is built.

    Args:
        moduleName(str): Library name to be build.
        debugMode(bool): Build library with debug flag.
        testMode(bool): Build tests for the library.
        withASAN(bool): Build with address sanitizer.

    Returns:
        None

    Raises:
        ValueError: Raises an exception

    Example:
        configureCMake("data_provider",
                        debugMode=True,
                        testMode=False,
                        withAsan=False)
    """
    utils.printSubHeader(moduleName, "configurecmake")
    currentModuleNameDir = utils.moduleDirPath(moduleName)
    currentPathDir = utils.moduleDirPathBuild(moduleName)

    if not os.path.exists(currentPathDir):
        os.mkdir(currentPathDir)

    configureCMakeCommand = "cmake -S {} -B {}"\
                            .format(currentModuleNameDir, currentPathDir)

    if debugMode:
        configureCMakeCommand += " -DCMAKE_BUILD_TYPE=Debug"

    if testMode:
        configureCMakeCommand += " -DUNIT_TEST=1"

    if withAsan:
        configureCMakeCommand += " -DFSANITIZE=1"

    out = subprocess.run(configureCMakeCommand, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True, check=True)
    if out.returncode == 0 and not out.stderr:
        utils.printGreen("[ConfigureCMake: PASSED]")
    else:
        print(configureCMakeCommand)
        print(out.stderr)
        utils.printFail("[ConfigureCMake: FAILED]")
        errorString = "Error Running ConfigureCMake: {}".format(out.returncode)
        raise ValueError(errorString)


def deleteFolderDic():
    """
    Get a map with configured folders to be deleted

    Args:
        None

    Returns:
        DELETE_FOLDER_DIC(map): Folders to each module to be deleted

    Raises:
        ValueError: Raises an exception
    """
    return DELETE_FOLDER_DIC


def makeDeps(targetName, srcOnly):
    """
    Get a map with configured folders to be deleted

    Args:
        targetName(str): Dependencies type to be build.
                         <agent, server, winagent>
        srcOnly(bool): Only builds external dependencies.

    Returns:
        None

    Raises:
        ValueError: Raises an exception

    Example:
        makeDeps("wazuh_modules/syscollector", srcOnly=True)
    """
    makeDepsCommand = "make deps TARGET={} -j4".format(targetName)
    if srcOnly:
        makeDepsCommand += " EXTERNAL_SRC_ONLY=yes"
    out = subprocess.run(makeDepsCommand, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True, check=True)
    if out.returncode == 0:
        utils.printGreen("[MakeDeps: PASSED]")
    else:
        print(makeDepsCommand)
        print(out.stderr)
        utils.printFail("[MakeDeps: FAILED]")
        errorString = "Error Running MakeDeps: {}".format(out.returncode)
        raise ValueError(errorString)


def makeLib(moduleName):
    """
    Build a library

    Args:
        moduleName(str): Library to be built.

    Returns:
        None

    Raises:
        ValueError: Raises an exception

    Example:
        makeLib("syscheckd")
    """
    command = "make -C {}".format(utils.moduleDirPathBuild(moduleName))
    utils.printSubHeader(moduleName, "make")

    out = subprocess.run(command, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True, check=True)
    if out.returncode != 0:
        print(command)
        print(out.stdout)
        print(out.stderr)
        errorString = "Error compiling library: {}".format(out.returncode)
        raise ValueError(errorString)
    utils.printGreen("[make: PASSED]")


def makeTarget(targetName, tests, debug):
    """
    Build project with flags

    Args:
        targetName(str): Build type to be built
                         <agent, server, winagent>
        tests(bool): Build all tests
        debug(bool): Build with debug binaries

    Returns:
        None

    Raises:
        ValueError: Raises an exception

    Example:
        makeTarget("winagent", tests=True, debug=True)
    """
    makeTargetCommand = "make TARGET={} -j4".format(targetName)
    if tests:
        makeTargetCommand += " TEST=1"
    if debug:
        makeTargetCommand += " DEBUG=1"

    out = subprocess.run(makeTargetCommand, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True, check=True)
    if out.returncode == 0:
        utils.printGreen("[MakeTarget: PASSED]")
    else:
        print(makeTargetCommand)
        print(out.stderr)
        utils.printFail("[MakeTarget: FAILED]")
        errorString = "Error Running MakeTarget: {}".format(out.returncode)
        raise ValueError(errorString)
