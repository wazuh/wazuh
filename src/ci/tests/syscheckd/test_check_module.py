"""
Copyright (C) 2015, Wazuh Inc.
March 30, 2022.

This program is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public
License (version 2) as published by the FSF - Free Software
Foundation.
"""

import logging
import logging.config
import os
import pytest
from ci import utils


@pytest.fixture(scope="session")
def smokeTestPath(getModuleName):
    """
    Find smokeTests inside the root path and return the complete path.

    Args:
        - moduleName(str): Library to be found smoke tests inside root
                           folder.

    Returns:
        - path(str): smokeTests full path.

    Raises:
        - None
    """
    return utils.findFolder(name="smokeTests",
                            path=os.path.join(utils.rootPath(),
                                              getModuleName))


@pytest.fixture(scope="session")
def configLogging(getModuleName):
    """
    Configure and format logging message.

    Args:
        - getModuleName(fixture): Return current module.

    Returns:
        - logger(obj): logger object to log messages.

    Raises:
        - None
    """
    moduleName = getModuleName
    # Create logger
    logger = logging.getLogger(moduleName)
    logger.setLevel(logging.DEBUG)

    # Create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # Create formatter
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")

    # Add formatter to ch
    ch.setFormatter(formatter)

    # Add ch to logger
    logger.addHandler(ch)

    return logger


@pytest.fixture(scope="session")
def findResultFolders(smokeTestPath):
    """
    Search inside test tool output folder so it returns the root path
    and the child folders.

    Args:
        - smokeTestPath(fixture): Return smoke tests full path.

    Returns:
        - rootDir(str): Base path.
        - dirs(arr): Folders found inside the smoke tests path

    Raises:
        - None
    """
    folder = smokeTestPath
    outputFolder = os.path.join(folder, "output")
    for rootDir, dirs, _ in os.walk(outputFolder):
        return rootDir, dirs


@pytest.fixture(scope="session")
def findPathResultsFolder(findResultFolders):
    """
    From directory name and their paths it creates  a map in order
    to have all information in only structure.

    Args:
        - findResultFolders(fixture): Return root path and subfolders
                                      path.

    Returns:
        - resultPathMap(map): A map with directory name like key and
                              directory path like value.

    Raises:
        - None
    """
    rootPath, dirs = findResultFolders
    resultPathMap = {}
    for directory in dirs:
        resultPathMap[directory] = os.path.join(rootPath, directory)

    return resultPathMap


@pytest.fixture(scope="function")
def readResultFiles(findPathResultsFolder):
    """
    From directory name and their paths it creates a map in order
    to have all information in only structure.

    Args:
        - findResultFolders(fixture): Return root path and subfolders
                                      path.

    Returns:
        - resultPathMap(map): A map with directory name like key and
                              directory path like value.

    Raises:
        - None
    """
    folderPathMap = findPathResultsFolder
    resultFiles = {}
    for folder in folderPathMap.keys():
        resultFiles[folder] = {}
        for rootDir, _, files in os.walk(folderPathMap[folder]):
            resultFiles[folder][rootDir] = files

    return resultFiles


@pytest.fixture(scope="function")
def readFileTxnInputs(smokeTestPath):
    """
    Read file transaction input files and return an array
    with these information in JSON format.

    Args:
        - smokeTestPath(fixture): Return smoke tests full path.

    Returns:
        - inputs(arr): An array with the json files read from
                       JSON inputs files.

    Raises:
        - None
    """
    rootPath = smokeTestPath
    path = os.path.join(rootPath, "FimDBTransaction")
    inputs = []
    inputs.append(utils.readJSONFile(
        jsonFilePath=os.path.join(path, "SyncTxnRows_1.json")))
    inputs.append(utils.readJSONFile(
        jsonFilePath=os.path.join(path, "SyncTxnRows_2.json")))

    return inputs


@pytest.fixture(scope="function")
def readRegistryKeyTxnInputs(smokeTestPath):
    """
    Read registry key transaction input files and return an array
    with these information in JSON format.

    Args:
        - smokeTestPath(fixture): Return smoke tests full path.

    Returns:
        - inputs(arr): An array with the json files read from
                       JSON inputs files.

    Raises:
        - None
    """
    rootPath = smokeTestPath
    path = os.path.join(rootPath, "FimDBTransaction")
    inputs = []
    inputs.append(utils.readJSONFile(
        jsonFilePath=os.path.join(path, "SyncTxnRowsRegistryKey_1.json")))
    inputs.append(utils.readJSONFile(
        jsonFilePath=os.path.join(path, "SyncTxnRowsRegistryKey_2.json")))

    return inputs


@pytest.fixture(scope="function")
def readRegistryValueTxnInputs(smokeTestPath):
    """
    Read registry value transaction input files and return an array
    with these information in JSON format.

    Args:
        - smokeTestPath(fixture): Return smoke tests full path.

    Returns:
        - inputs(arr): An array with the json files read from
                       JSON inputs files.

    Raises:
        - None
    """
    rootPath = smokeTestPath
    path = os.path.join(rootPath, "FimDBTransaction")
    inputs = []
    inputs.append(utils.readJSONFile(
        jsonFilePath=os.path.join(path, "SyncTxnRowsRegistryData_1.json")))
    inputs.append(utils.readJSONFile(
        jsonFilePath=os.path.join(path, "SyncTxnRowsRegistryData_2.json")))

    return inputs


def readResults(readResultFiles, testCase):
    """
    Read registry value transaction input files and return an array
    with these information in JSON format.

    Args:
        - readResultFiles(fixture): Return a map with name like key and
                                    path like value.
        - testCase(str): Key to find inside the map.

    Returns:
        - results(map): this is a map with actions and txn executed
                        like key and an array with the json results.

    Raises:
        - None
    """
    resultFiles = readResultFiles
    results = {'actions': [], 'txnActions': []}
    for rootPath, files in resultFiles[testCase].items():
        for file in files:
            path = os.path.join(rootPath, file)
            if "action" in file:
                results['actions'].append(utils.readJSONFile(
                    jsonFilePath=path))
            else:
                results['txnActions'].append(utils.readJSONFile(
                    jsonFilePath=path))

    return results


def checkResult(result, configLogging, testCase):
    """
    Check result of action executed.

    Args:
        - result(map): A map with parsed result JSON.
        - configLogging(fixture): Configure and format logging message.
        - testCase(str): Key to find inside the map.

    Returns:
        - None

    Raises:
        - None
    """
    logger = configLogging
    logger.info("{0:>20} {1:>20}\t\t\t\t{2}".format(testCase,
                                                    result['action'],
                                                    result['result']))
    assert result['result']


def checkTransactionOp(result, configLogging, testCase, inputJSONs):
    """
    Check result of transaction executed compared than input information.

    Args:
        - result(map): A map with parsed result JSON.
        - configLogging(fixture): Configure and format logging message.
        - testCase(str): Key to find inside the map.
        - inputJSONs(map): A map with parsed input JSON.

    Returns:
        - None

    Raises:
        - None
    """
    logger = configLogging
    for inputData in inputJSONs:
        if result['value'] == inputData['body']['data'][0]:
            assert True
            break
    else:
        assert False

    logger.info("{0:>20} {1:>20}\t\t\t\t{2}".format(testCase,
                                                    inputData['action'],
                                                    "true"))


def testAtomicActions(readResultFiles, configLogging):
    """
    Check atomic actions executed in test tool for FIM module

    Steps:
        - Read result JSON files.
        - Create structure necessary in order to test result files.
        - Check the result and log the information.

    Fixtures:
        - readResultFiles: Return a map with name like key and
                           path like value.
        - configLogging: Configure and format logging message.
    """
    testCase = "AtomicOperations"
    results = readResults(readResultFiles=readResultFiles,
                          testCase=testCase)
    print("")
    for result in results['actions']:
        checkResult(result=result,
                    configLogging=configLogging,
                    testCase=testCase)


def testFileTransactions(readResultFiles, configLogging, readFileTxnInputs):
    """
    Check operations executed inside a transaction from file in test tool
    for FIM module.

    Steps:
        - Read result JSON files.
        - Read input JSON files
        - Create structure necessary in order to test result files.
        - Check the result and compare with input files and log
          the information.

    Fixtures:
        - readResultFiles: Return a map with name like key and
                           path like value.
        - configLogging: Configure and format logging message.
        - readFileTxnInputs: Return an array with the json files read from
                             JSON inputs files.
    """
    logger = configLogging
    testCase = "fileTransaction"
    inputJSONs = readFileTxnInputs
    results = readResults(readResultFiles=readResultFiles,
                          testCase=testCase)
    resultTransactions = results['txnActions'][0]['data']
    print("")
    for result in results['actions']:
        checkResult(result=result,
                    configLogging=configLogging,
                    testCase=testCase)

    for operation in resultTransactions:
        assert "DB_ERROR" != operation['Operation type'],\
               "Something has gone wrong with the test tool\
               \n {}".format(operation['value']['exception'])

        if "INSERTED" in operation['Operation type']:
            checkTransactionOp(result=operation,
                               configLogging=configLogging,
                               testCase=testCase,
                               inputJSONs=inputJSONs)
        elif "DELETED" in operation['Operation type']:
            assert operation['value']['path'] == "/tmp/test_1.txt"
            logger.info("{0:>20} {1:>20}\t\t\t\t{2}"
                        .format(testCase,
                                operation['action'],
                                "true"))


def testRegistryKeytransactions(readResultFiles,
                                configLogging,
                                readRegistryKeyTxnInputs):
    """
    Check operations executed inside a transaction from registry key
    in test tool for Windows on FIM module.

    Steps:
        - Read result JSON files.
        - Read input JSON files
        - Create structure necessary in order to test result files.
        - Check the result and compare with input files and log
          the information.

    Fixtures:
        - readResultFiles: Return a map with name like key and
                           path like value.
        - configLogging: Configure and format logging message.
        - readRegistryKeyTxnInputs: Return an array with the json files read from
                                    JSON inputs files.
    """
    logger = configLogging
    testCase = "registryKeyTransaction"
    inputJSONs = readRegistryKeyTxnInputs
    results = readResults(readResultFiles=readResultFiles,
                          testCase=testCase)
    resultTransactions = results['txnActions'][0]['data']
    print("")
    for result in results['actions']:
        checkResult(result=result,
                    configLogging=configLogging,
                    testCase=testCase)

    for operation in resultTransactions:
        assert "DB_ERROR" != operation['Operation type'],\
               "Something has gone wrong with the test tool\
               \n {}".format(operation['value']['exception'])

        if "INSERTED" in operation['Operation type']:
            checkTransactionOp(result=operation,
                               configLogging=configLogging,
                               testCase=testCase,
                               inputJSONs=inputJSONs)
        if "DELETED" in operation['Operation type']:
            assert operation['value']['path'] == "HKEY_LOCAL_MACHINE\\SOFTWARE"
            assert operation['value']['arch'] == "[x64]"
            logger.info("{0:>20} {1:>20}\t\t\t\t{2}"
                        .format(testCase,
                                operation['action'],
                                "true"))


def testRegistryDatatransactions(readResultFiles,
                                 configLogging,
                                 readRegistryValueTxnInputs):
    """
    Check operations executed inside a transaction from registry value
    in test tool for Windows on FIM module.

    Steps:
        - Read result JSON files.
        - Read input JSON files
        - Create structure necessary in order to test result files.
        - Check the result and compare with input files and log
          the information.

    Fixtures:
        - readResultFiles: Return a map with name like key and
                           path like value.
        - configLogging: Configure and format logging message.
        - readRegistryValueTxnInputs: Return an array with the json files read from
                                      JSON inputs files.
    """
    logger = configLogging
    testCase = "registryDataTransaction"
    inputJSONs = readRegistryValueTxnInputs
    results = readResults(readResultFiles=readResultFiles,
                          testCase=testCase)
    resultTransactions = results['txnActions'][0]['data']
    print("")
    for result in results['actions']:
        checkResult(result=result,
                    configLogging=configLogging,
                    testCase=testCase)

    for operation in resultTransactions:
        assert "DB_ERROR" != operation['Operation type'],\
               "Something has gone wrong with the test tool\
               \n {}".format(operation['value']['exception'])
        if "INSERTED" in operation['Operation type']:
            checkTransactionOp(result=operation,
                               configLogging=configLogging,
                               testCase=testCase,
                               inputJSONs=inputJSONs)
        if "DELETED" in operation['Operation type']:
            assert operation['value']['path'] == "/tmp/pathTestRegistry"
            assert operation['value']['name'] == "testRegistry"
            assert operation['value']['arch'] == "[x64]"
            logger.info("{0:>20} {1:>20}\t\t\t\t{2}"
                        .format(testCase,
                                operation['action'],
                                "true"))
