import os
import subprocess
from ci import utils


DELETEFOLDERDIC = {
    'wazuh_modules/syscollector':   ['build', 'smokeTests/output'],
    'shared_modules/dbsync':        ['build', 'smokeTests/output'],
    'shared_modules/rsync':         ['build', 'smokeTests/output'],
    'data_provider':                ['build', 'smokeTests/output'],
    'shared_modules/utils':         ['build'],
    'syscheckd':                    ['build', 'src/db/smokeTests/output',
                                     'coverage_report'],
}

def getDeleteFolderDic():
    return DELETEFOLDERDIC


def makeLib(moduleName):
    """
    Builds the 'moduleName' lib.

    :param moduleName: Lib to be built.
    """
    command = f'make -C {utils.currentDirPathBuild(moduleName)}'
    utils.printHeader(moduleName, 'make')

    out = subprocess.run(command, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)
    if out.returncode != 0:
        print(command)
        print(out.stdout)
        print(out.stderr)
        errorString = f'Error compiling library: {str(out.returncode)}'
        raise ValueError(errorString)
    utils.printGreen(f'{moduleName} > [make: PASSED]')


def cleanLib(moduleName):
    """
    Cleans the 'moduleName' generated files.

    :param moduleName: Lib to be clean.
    """
    currentDir = utils.currentDirPathBuild(moduleName)
    os.system('make clean -C' + currentDir)


def cleanInternals():
    out = subprocess.run("make clean-internals",
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         shell=True)
    if out.returncode == 0:
        utils.printGreen('[CleanInternals: PASSED]')
    else:
        print("make clean-internals")
        print(out.stderr)
        utils.printFail('[CleanInternals: FAILED]')
        errorString = 'Error Running CleanInternals: ' + str(out.returncode)
        raise ValueError(errorString)


def cleanAll():
    out = subprocess.run("make clean", stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0:
        utils.printGreen('[CleanAll: PASSED]')
    else:
        print("make clean")
        print(out.stderr)
        utils.printFail('[CleanAll: FAILED]')
        errorString = 'Error Running CleanAll: ' + str(out.returncode)
        raise ValueError(errorString)


def cleanExternals():
    out = subprocess.run("rm -rf ./external/*",
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0 and not out.stderr:
        utils.printGreen('[CleanExternals: PASSED]')
    else:
        print("rm -rf ./external/*")
        print(out.stderr)
        utils.printFail('[CleanExternals: FAILED]')
        errorString = 'Error Running CleanExternals: ' + str(out.returncode)
        raise ValueError(errorString)


def makeDeps(targetName, srcOnly):
    makeDepsCommand = "make deps TARGET=" + targetName + " -j4"
    if srcOnly:
        makeDepsCommand += " EXTERNAL_SRC_ONLY=yes"
    out = subprocess.run(makeDepsCommand, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0:
        utils.printGreen('[MakeDeps: PASSED]')
    else:
        print(makeDepsCommand)
        print(out.stderr)
        utils.printFail('[MakeDeps: FAILED]')
        errorString = 'Error Running MakeDeps: ' + str(out.returncode)
        raise ValueError(errorString)


def makeTarget(targetName, tests, debug):
    makeTargetCommand = "make TARGET=" + targetName + " -j4"
    if tests:
        makeTargetCommand += " TEST=1"
    if debug:
        makeTargetCommand += " DEBUG=1"

    out = subprocess.run(makeTargetCommand,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0:
        utils.printGreen('[MakeTarget: PASSED]')
    else:
        print(makeTargetCommand)
        print(out.stderr)
        utils.printFail('[MakeTarget: FAILED]')
        errorString = 'Error Running MakeTarget: ' + str(out.returncode)
        raise ValueError(errorString)


def configureCMake(moduleName, debugMode, testMode, withAsan):
    utils.printHeader(moduleName, 'configurecmake')
    currentModuleNameDir = utils.currentDirPath(moduleName)
    currentPathDir = utils.currentDirPathBuild(moduleName)

    if not os.path.exists(currentPathDir):
        os.mkdir(currentPathDir)

    configureCMakeCommand = "cmake -S"
    configureCMakeCommand += currentModuleNameDir
    configureCMakeCommand += " -B"
    configureCMakeCommand += currentPathDir

    if debugMode:
        configureCMakeCommand += " -DCMAKE_BUILD_TYPE=Debug"

    if testMode:
        configureCMakeCommand += " -DUNIT_TEST=1"

    if withAsan:
        configureCMakeCommand += " -DFSANITIZE=1"

    out = subprocess.run(configureCMakeCommand,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)
    if out.returncode == 0 and not out.stderr:
        utils.printGreen('[ConfigureCMake: PASSED]')
    else:
        print(configureCMakeCommand)
        print(out.stderr)
        utils.printFail('[ConfigureCMake: FAILED]')
        errorString = 'Error Running ConfigureCMake: ' + str(out.returncode)
        raise ValueError(errorString)


def cleanFolder(moduleName, additionalFolder, folderName=""):

    currentDir = utils.currentDirPath(moduleName)
    cleanFolderCommand = f'rm -rf {os.path.join(currentDir, additionalFolder)}'

    if DELETEFOLDERDIC[moduleName].count(additionalFolder) > 0:
        out = subprocess.run(cleanFolderCommand,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        if out.returncode == 0 and not out.stderr:
            utils.printGreen('[Cleanfolder {}: PASSED]'.format(folderName))
        else:
            print(cleanFolderCommand)
            print(out.stderr)
            utils.printFail('[Cleanfolder {}: FAILED]'.format(folderName))
            errorString = 'Error Running Cleanfolder: ' + str(out.returncode)
            raise ValueError(errorString)
    else:
        utils.printFail('[Cleanfolder {}: FAILED]'.format(folderName))
        errorString = 'Error Running Cleanfolder: additional folder\
                       not exist in delete folder dictionary.'
        raise ValueError(errorString)
