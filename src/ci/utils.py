# Copyright (C) 2015, Wazuh Inc.
# All right reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation

import os
from ci import build_tools
from pathlib import Path

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


def rootPath():
    return str(CURRENT_DIR.parent)


def currentDirPath(moduleName):
    """
    Gets the current dir path based on 'moduleName'

    :param moduleName: Lib to get the path of.
    :return Lib dir path
    """
    currentDir = os.path.join(CURRENT_DIR.parent, str(moduleName))
    if str(moduleName) == "shared_modules/utils":
        currentDir = os.path.join(currentDir, "tests/")

    return currentDir


def currentDirPathBuild(moduleName):
    """
    Gets the current dir path build based on 'moduleName'

    :param moduleName: Lib to get the path of.
    :return Lib dir path build folder
    """
    currentDir = currentDirPath(moduleName)
    return os.path.join(currentDir, "build")


def getFoldersToAStyle(moduleName):
    """
    Returns the folders to be analyzed with AStyle coding style analysis tool.

    :param moduleName: Lib to be analyzed using AStyle coding style
    analysis tool.
    :return specific folders and files to be analyzed.
    """
    printHeader(moduleName, "AStyle")
    build_tools.cleanFolder(str(moduleName), "build")

    foldersToScan = ""
    if str(moduleName) == "shared_modules/utils":
        foldersToScan = "{}/../*.h {}/*.cpp".format(moduleName, moduleName)
    elif str(moduleName) == "syscheckd":
        foldersToScan = "\"{}/src/db/src/*.hpp\" \"{}/src/db/src/*.cpp\""\
                        .format(moduleName, moduleName)
    else:
        foldersToScan = "{}/*.h {}/*.cpp".format(moduleName, moduleName)
    return foldersToScan


def deleteLogs(moduleName):
    printHeader(moduleName, "deletelogs")
    deleteFolderDic = build_tools.getDeleteFolderDic()
    for folder in deleteFolderDic[moduleName]:
        build_tools.cleanFolder(str(moduleName), folder, folder)


def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)


def printGreen(msg, module=""):
    if module=="":
        formatMsg = msg
    else:
        formatMsg = "<{}>{}<{}>".format(module, msg, module)
    print("\033[92m {} \033[0m".format(formatMsg))

def printHeader(moduleName, header_key):
    msg = "<{}>{}<{}>".format(moduleName, HEADER_DIR[header_key], moduleName)
    print("\033[95m {} \033[0m".format(msg))

def printSubHeader(moduleName, header_key):
    msg = "<{}>{}<{}>".format(moduleName, HEADER_DIR[header_key], moduleName)
    print("\033[;36m {}".format(msg))

def printFail(msg):
    print("\033[91m {} \033[0m".format(msg))

def printInfo(msg):
    print("\033[1;33m {} \033[0m".format(msg))
