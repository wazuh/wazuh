"""
Copyright (C) 2015, Wazuh Inc.
March 28, 2022.

This program is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public
License (version 2) as published by the FSF - Free Software
Foundation.
"""
import json
import os
import subprocess
import multiprocessing
from pathlib import Path
from ci import build_tools
import functools
print = functools.partial(print, flush=True)

# Constant values
CURRENT_DIR = Path(__file__).parent
HEADER_DIR = {
    'asan':                "=============== Running ASAN        ===============",
    'AStyle':              "=============== Running AStyle      ===============",
    'clean':               "=============== Cleaning library    ===============",
    'cleanfolder':         "=============== Clean build Folders ===============",
    'cppcheck':            "=============== Running cppcheck    ===============",
    'configurecmake':      "=============== Running CMake Conf  ===============",
    'coverage':            "=============== Running Coverage    ===============",
    'deletelogs':          "=============== Clean result folders ==============",
    'make':                "=============== Compiling library   ===============",
    'makeAll':             "=============== Running Make project ==============",
    'makeDeps':            "=============== Running Make Deps   ===============",
    'rtr':                 "=============== Running RTR checks  ===============",
    'scanbuild':           "=============== Running Scanbuild   ===============",
    'tests':               "=============== Running Tests       ===============",
    'winagentTests':       "=============== Running Windows Agent Tests =======",
    'testtool':            "=============== Running TEST TOOL   ===============",
    'valgrind':            "=============== Running Valgrind    ===============",
    'wintesttool':         "=============== Running TEST TOOL for Windows ====="
}
MODULE_LIST = ['wazuh_modules/syscollector', 'shared_modules/dbsync',
               'shared_modules/rsync', 'data_provider', 'syscheckd',
               'sync_protocol']
MODULE_LIST_STR = '|'.join(MODULE_LIST)
TARGET_LIST = ['agent', 'server', 'winagent']


def currentPath():
    """
    Get current path.

    Args:
        - None

    Returns:
        - path(str): Current path.

    Raises:
        - None
    """
    return CURRENT_DIR


def deleteLogs(moduleName):
    """
    Delete logs generates for a module.

    Args:
        - moduleName(str): Library to be cleaned.

    Returns:
        - None

    Raises:
        - None
    """
    printHeader(moduleName=moduleName,
                headerKey="deletelogs")
    deleteFolderDic = build_tools.deleteFolderDic()
    for folder in deleteFolderDic[moduleName]:
        if (os.path.exists(folder)):
            build_tools.cleanFolder(moduleName,
                                    folder,
                                    folder)
    pytestResultsPath = os.path.join(CURRENT_DIR,
                                     "tests/results")
    out = subprocess.run("rm -rf {}".format(pytestResultsPath),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True,
                         check=False)
    if out.returncode == 0:
        printGreen(msg="[{}{}: PASSED]".format("Cleanfolder ",
                                               pytestResultsPath))
    else:
        print(out.stdout.decode('utf-8','replace'))
        print(out.stderr.decode('utf-8','replace'))
        printFail(msg="[{}{}: FAILED]".format("Cleanfolder ",
                                              pytestResultsPath))
        errorString = "Error cleaning tests/results: {}".format(out.returncode)
        raise ValueError(errorString)


def findFile(name, path):
    """
    Find a file in some path.

    Args:
        - name(str): File to find.
        - path(str): Base path to find a file.

    Returns:
        - path(str): File path if not found return empty string.

    Raises:
        - None

    Example:
        findFile(hello_world, "/home")
    """
    for root, _, files in os.walk(path):
        if name in files:
            return os.path.join(root,
                                name)

    return ""


def findFolder(name, path):
    """
    Find a folder in some path.

    Args:
        - name(str): Folder to find.
        - path(str): Base path to find a folder.

    Returns:
        - path(str): Folder path if not found return empty string

    Raises:
        - None

    Example:
        findFolder(hello_world, "/home")
    """
    for rootdir, dirs, _ in os.walk(path):
        for subdir in dirs:
            if name in subdir:
                return os.path.join(rootdir,
                                    subdir)

    return ""


def getFoldersToAStyle(moduleName):
    """
    Return folders to be analyzed with AStyle coding style analysis tool.

    Args:
        - moduleName(str): Library to be analyzed using AStyle coding style
                           analysis tool.

    Returns:
        - foldersToScan(str): specific folders and files to be analyzed.

    Raises:
        - None
    """
    printHeader(moduleName=moduleName,
                headerKey="AStyle")
    build_tools.cleanFolder(moduleName,
                            "build")

    foldersToScan = ""
    if str(moduleName) == "shared_modules/utils":
        foldersToScan = "'{0}/*.h' '{0}/*.cpp' '{0}/*.hpp'".format(moduleName)
    elif str(moduleName) == "syscheckd":
        foldersToScan = "\"{0}/src/db/src/*.hpp\" \"{0}/src/db/src/*.cpp\""\
                        .format(moduleName)
    elif str(moduleName) == "sync_protocol":
        foldersToScan = "\"{0}/include/*.hpp\" \"{0}/src/*.cpp\""\
                        .format(moduleName)
    else:
        foldersToScan = "{0}/*.h {0}/*.cpp {0}/*.hpp".format(moduleName)

    return foldersToScan


def moduleDirPath(moduleName):
    """
    Get directory path for a module.

    Args:
        - moduleName(str): Library to get the path of.

    Returns:
        - path(str): Library directory path.

    Raises:
        - None
    """
    path = os.path.join(CURRENT_DIR.parent,
                        moduleName)
    if str(moduleName) == "shared_modules/utils":
        return os.path.join(path,
                            "tests/")

    return path


def moduleDirPathBuild(moduleName):
    """
    Get directory path build for a module.

    Args:
        moduleName(str): Library to get the path of.

    Returns:
        path(str): Library directory path build folder.

    Raises:
        - None
    """
    path = moduleDirPath(moduleName=moduleName)

    return os.path.join(path,
                        "build")


def moduleList():
    """
    Get valid module list.

    Args:
        - None

    Returns:
        - MODULE_LIST(array): A list with valid modules.

    Raises:
        - None
    """
    return MODULE_LIST


def moduleListStr():
    """
    Get valid module list.

    Args:
        - None

    Returns:
        - MODULE_LIST_STR(str): A list with valid modules.

    Raises:
        - None
    """
    return MODULE_LIST_STR


def printFail(msg):
    """
    Display a red message with the errors.

    Args:
        - msg(str): Message to show.

    Returns:
        - None

    Raises:
        - None
    """
    print("\033[91m {} \033[0m".format(msg))


def printGreen(msg, module=""):
    """
    Display a formatted green message.

    Args:
        - msg(str): Message to show.
        - module(str): Library using in the message.

    Returns:
        - None

    Raises:
        - None
    """
    if not module:
        formatMsg = msg
    else:
        formatMsg = "<{0}>{1}<{0}>".format(module, msg)
    print("\033[92m {} \033[0m".format(formatMsg))


def printHeader(moduleName, headerKey):
    """
    Display a message formatted from the HEADER_DIR map.

    Args:
        - moduleName(str): Library using in the message.
        - headerKey(str): Message key to find inside HEADER_DIR.

    Returns:
        - None

    Raises:
        - None
    """
    msg = "<{0}>{1}<{0}>".format(moduleName, HEADER_DIR[headerKey])
    print("\033[95m {} \033[0m".format(msg))


def printInfo(msg):
    """
    Display a yellow message with some information.

    Args:
        - msg(str): Message to show.

    Returns:
        - None

    Raises:
        - None
    """
    print("\033[1;33m {} \033[0m".format(msg))


def printSubHeader(moduleName, headerKey):
    """
    Display a message formatted from the HEADER_DIR map.

    Args:
        - moduleName(str): Library using in the message.
        - headerKey(str): Message key to find inside HEADER_DIR.

    Returns:
        - None

    Raises:
        - None
    """
    msg = "<{0}>{1}<{0}>".format(moduleName, HEADER_DIR[headerKey])
    print("\033[;36m {}".format(msg))


def readJSONFile(jsonFilePath):
    """
    Read a JSON path and convert to map.

    Args:
        - jsonFilePath(str): JSON path.

    Returns:
        - jsonToMap(map): map with JSON loaded.

    Raises:
        - IOError: Raises an exception when file config cannot open.
    """
    try:
        with open(jsonFilePath, "r") as readFile:
            jsonToMap = json.load(readFile)
    except IOError as exception:
        raise exception
    finally:
        readFile.close()

    return jsonToMap


def rootPath():
    """
    Get root path.

    Args:
        - None

    Returns:
        - path(str): Root path.

    Raises:
        - None
    """
    return CURRENT_DIR.parent


def targetList():
    """
    Get possible build targets.

    Args:
        - None

    Returns:
        - TARGET_LIST(array): Target list

    Raises:
        - None
    """
    return TARGET_LIST

def initializeCpuCores():
    global CPU_CORES
    CPU_CORES = multiprocessing.cpu_count()

def setCpuCores(cpuCores):
    global CPU_CORES
    if cpuCores.isdigit():
        CPU_CORES = cpuCores

def getCpuCores():
    global CPU_CORES
    return CPU_CORES
