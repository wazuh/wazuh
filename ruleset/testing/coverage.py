import argparse
from os import strerror
from os import path as Path
from os import listdir
import errno
import re

def checkDir(path):
    """
    Check if given path is a directory.

    Parameters
    ----------
    path : str
        The path to be checked.

    Raises
    ------
    FileNotFoundError
        If path doesn't exists.

    NotADirectoryError
        If path is not a directory.
    """
    if not Path.exists(path):
        raise FileNotFoundError(errno.ENOENT, strerror(errno.ENOENT), path)

    if not Path.isdir(path):
        raise NotADirectoryError(errno.ENOTDIR, strerror(errno.ENOTDIR), path)

def getRuleIds(rulesPath):
    """
    Get a set with all rule ids found on given directory path.

    Parameters
    ----------
    rulesPath : str
        Path of the directory with rule files.

    Returns
    -------
    set
        Set with all rule ids found. Empty set if none found.

    Raises
    ------
    FileNotFoundError
        If path doesn't exists.

    NotADirectoryError
        If path is not a directory.
    """
    checkDir(rulesPath)

    ruleSet = set()

    ruleStartPattern = re.compile(r'^\s*<rule\sid="(\d+)"', re.MULTILINE)

    for filename in listdir(rulesPath):
        if Path.isfile(rulesPath+filename):
            with open(rulesPath+filename,'r') as ruleFile:
                ruleSet.update( {match for match in re.findall(ruleStartPattern, ruleFile.read())} )

    return ruleSet

def getParentDecoderNames(decodersPath):
    """
    Get a set with all parent decoder names found on given directory path.

    Parameters
    ----------
    decodersPath : str
        Path of the directory with decoder files.

    Returns
    -------
    set
        Set with all parent decoder names found. Empty set if none found.

    Raises
    ------
    FileNotFoundError
        If path doesn't exists.

    NotADirectoryError
        If path is not a directory.
    """
    checkDir(decodersPath)

    decoderSet = set()
    decoderStartPattern = re.compile(r'^\s*<decoder\sname="(.+)">')
    decoderEndPattern = re.compile(r'^\s*</decoder>')
    parentDecoderPattern = re.compile(r'^\s*<parent>')

    for filename in listdir(decodersPath):
        if Path.isfile(decodersPath+filename):
            with open(decodersPath+filename,'r') as decoderFile:
                insideDecoder = False
                parentFound = False
                decoderName = None
                for line in decoderFile:
                    if not insideDecoder:
                        decoderName = re.match(decoderStartPattern, line)
                        if decoderName:
                            insideDecoder = True
                            decoderName = decoderName.group(1)
                    elif not parentFound and re.match(parentDecoderPattern, line):
                        parentFound = True
                    elif re.match(decoderEndPattern, line):
                        if not parentFound:
                            decoderSet.add(decoderName)
                        else:
                            parentFound = False

                        insideDecoder = False

    return decoderSet


def main(testsPath, rulesetPath, outputPath):
    ruleSet = getRuleIds(rulesetPath + "rules/")
    parentDecoderSet = getParentDecoderNames(rulesetPath + "decoders/")

    print(len(ruleSet))
    print(len(parentDecoderSet))

if __name__ == "__main__":
    # Console arguments definition
    parser = argparse.ArgumentParser(
        prog="mitre_mapping.py",
        description='Script to update ruleset mitre mappings from csv file')

    parser.add_argument("tests_path", help="path were ini test files are located")
    parser.add_argument("ruleset_path", help="path were ruleset is located")
    parser.add_argument("-o", "--output", help="output directory with coverage results", default=None)

    args = parser.parse_args()
    main(args.tests_path, args.ruleset_path, args.output)

