"""
Copyright (C) 2015, Wazuh Inc.
March 28, 2022.

This program is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public
License (version 2) as published by the FSF - Free Software
Foundation.
"""

import os
from pathlib import Path
from ci import build_tools

CURRENT_DIR = Path(__file__).parent
HEADER_DIR = {
    'tests':            "=============== Running Tests       ===============",
    'valgrind':         "=============== Running Valgrind    ===============",
    'cppcheck':         "=============== Running cppcheck    ===============",
    'asan':             "=============== Running ASAN        ===============",
    'wintests':         "=============== Running TEST TOOL for Windows =====",
    'scanbuild':        "=============== Running Scanbuild   ===============",
    'testtool':         "=============== Running TEST TOOL   ===============",
    'cleanfolder':      "=============== Clean build Folders ===============",
    'configurecmake':   "=============== Running CMake Conf  ===============",
    'make':             "=============== Compiling library   ===============",
    'clean':            "=============== Cleaning library    ===============",
    'rtr':              "=============== Running RTR checks  ===============",
    'coverage':         "=============== Running Coverage    ===============",
    'AStyle':           "=============== Running AStyle      ===============",
    'deletelogs':       "=============== Clean result folders =============="
}
MODULE_LIST = ['wazuh_modules/syscollector', 'shared_modules/dbsync',
               'shared_modules/rsync', 'shared_modules/utils',
               'data_provider', 'syscheckd']
MODULE_LIST_STR = '|'.join(MODULE_LIST)


def argIsValid(arg):
    """
    Checks if the argument being selected is a correct one.

    Args:
        arg(str): Argument being selected in the command line.

    Return
        validArg(bool): True is 'arg' is a correct one, False otherwise.
    """
    return arg in MODULE_LIST


def currentPath():
    """
    Get current path.

    Args:
        None

    Returns:
        path(str): Current path.
    """
    return str(CURRENT_DIR)


def deleteLogs(moduleName):
    """
    Delete logs generates for a module.

    Args:
        moduleName(str): Library to be cleaned.

    Returns:
        None
    """
    printHeader(moduleName, "deletelogs")
    deleteFolderDic = build_tools.deleteFolderDic()
    for folder in deleteFolderDic[moduleName]:
        build_tools.cleanFolder(str(moduleName), folder, folder)


def find(name, path):
    """
    Find a file in some path.

    Args:
        name(str): File to find.
        path(str): Base path to find a file.

    Returns:
        path(str): File path

    Example:
        find("/home", hello_world)
    """
    for root, _, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)
    return ""


def getFoldersToAStyle(moduleName):
    """
    Return folders to be analyzed with AStyle coding style analysis tool.

    Args:
        moduleName(str): Library to be analyzed using AStyle coding style
                         analysis tool.

    Returns:
        foldersToScan(str): specific folders and files to be analyzed.
    """
    printHeader(moduleName, "AStyle")
    build_tools.cleanFolder(str(moduleName), "build")

    foldersToScan = ""
    if str(moduleName) == "shared_modules/utils":
        foldersToScan = "{0}/../*.h {0}/*.cpp".format(moduleName)
    elif str(moduleName) == "syscheckd":
        foldersToScan = "\"{0}/src/db/src/*.hpp\" \"{0}/src/db/src/*.cpp\""\
                        .format(moduleName)
    else:
        foldersToScan = "{0}/*.h {0}/*.cpp".format(moduleName)
    return foldersToScan


def moduleDirPath(moduleName):
    """
    Get directory path for a module

    Args:
        moduleName(str): Library to get the path of.

    Returns:
        path(str): Library directory path
    """
    path = os.path.join(CURRENT_DIR.parent, str(moduleName))
    if str(moduleName) == "shared_modules/utils":
        return os.path.join(path, "tests/")

    return path


def moduleDirPathBuild(moduleName):
    """
    Get directory path build for a module.

    Args:
        moduleName(str): Library to get the path of.

    Returns:
        path(str): Library directory path build folder
    """
    path = moduleDirPath(moduleName)

    return os.path.join(path, "build")


def moduleList():
    """
    Get valid module list.

    Args:
        None

    Returns:
        moduleList(str): A list with valid modules.
    """
    return MODULE_LIST_STR


def printFail(msg):
    """
    Display a red message with the errors.

    Args:
        msg(str): Message to show.

    Returns:
        None
    """
    print("\033[91m {} \033[0m".format(msg))


def printGreen(msg, module=""):
    """
    Display a formatted green message.

    Args:
        msg(str): Message to show.
        module(str): Library using in the message.

    Returns:
        None
    """
    if module == "":
        formatMsg = msg
    else:
        formatMsg = "<{0}>{1}<{0}>".format(module, msg)
    print("\033[92m {} \033[0m".format(formatMsg))


def printHeader(moduleName, headerKey):
    """
    Display a message formatted from the HEADER_DIR map.

    Args:
        moduleName(str): Library using in the message.
        headerKey(str): Message key to find inside HEADER_DIR.

    Returns:
        None
    """
    msg = "<{0}>{1}<{0}>".format(moduleName, HEADER_DIR[headerKey])
    print("\033[95m {} \033[0m".format(msg))


def printInfo(msg):
    """
    Display a yellow message with some information.

    Args:
        msg(str): Message to show.

    Returns:
        None
    """
    print("\033[1;33m {} \033[0m".format(msg))


def printSubHeader(moduleName, headerKey):
    """
    Display a message formatted from the HEADER_DIR map.

    Args:
        moduleName(str): Library using in the message.
        headerKey(str): Message key to find inside HEADER_DIR.

    Returns:
        None
    """
    msg = "<{0}>{1}<{0}>".format(moduleName, HEADER_DIR[headerKey])
    print("\033[;36m {}".format(msg))


def rootPath():
    """
    Get root path.

    Args:
        None

    Returns:
        path(str): Root path.
    """
    return str(CURRENT_DIR.parent)


def targetIsValid(arg):
    """
    Checks if the argument being selected is a correct one.

    Args:
        arg(str): Argument being selected in the command line.

    Returns:
        argValid(bool): True is 'arg' is a correct one, False otherwise.
    """
    validArguments = ['agent',
                      'server',
                      'winagent']
    return arg in validArguments
