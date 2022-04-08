"""
Copyright (C) 2015, Wazuh Inc.
All right reserved.

This program is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public
License (version 2) as published by the FSF - Free Software
Foundation
"""

import argparse
from ci import build_tools
from ci import run_check
from ci import utils


def processArgs():
    """
    Process the command line arguments and executes the corresponding
    argument's utility.

    Args:
        - None

    Returns:
        - None

    Raises:
        - None
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--readytoreview",
                        help="Run all the quality checks needed to \
                              create a PR. Example: python3 build.py \
                              -r <{}>".format(utils.moduleList()))
    parser.add_argument("-d", "--deleteLogs",
                        help="Clean log results. Example: python3 \
                              build.py -d <{}>".format(utils.moduleList()))
    parser.add_argument("-rc", "--readytoreviewandclean",
                        help="Run all the quality checks needed to \
                              create a PR and clean results. Example: \
                              python3 build.py -rc <{}>"
                        .format(utils.moduleList()))
    parser.add_argument("-m", "--make",
                        help="Compile the lib. Example: python3 build.py\
                              -m <{}>".format(utils.moduleList()))
    parser.add_argument("-t", "--tests",
                        help="Run tests (should be configured with \
                              TEST=on). Example: python3 build.py -t\
                              <{}>".format(utils.moduleList()))
    parser.add_argument("-c", "--coverage",
                        help="Collect tests coverage and generates\
                              report. Example: python3 build.py -c <{}>"
                              .format(utils.moduleList()))
    parser.add_argument("-v", "--valgrind",
                        help="Run valgrind on tests. Example: python3 \
                              build.py -v <{}>".format(utils.moduleList()))
    parser.add_argument("--clean",
                        help="Clean the lib. Example: python3 build.py \
                              --clean <{}>".format(utils.moduleList()))
    parser.add_argument("--cppcheck",
                        help="Run cppcheck on the code. Example: python3 \
                              build.py --cppcheck <{}>"
                        .format(utils.moduleList()))
    parser.add_argument("--asan",
                        help="Run ASAN on the code. Example: python3 \
                              build.py --asan <{}> --path /home/test"
                        .format(utils.moduleList()))
    parser.add_argument("--path",
                        help="Add path to configure test tool to run ASAN\
                              on the code. Example: python3 build.py \
                              --asan <{}> --path /home/test"
                        .format(utils.moduleList()))
    parser.add_argument("--scheck",
                        help="Run AStyle on the code for checking \
                              purposes. Example: python3 build.py \
                              --scheck <{}>".format(utils.moduleList()))
    parser.add_argument("--sformat",
                        help="Run AStyle on the code formatting the \
                              needed files. Example: python3 build.py \
                              --sformat <{}>".format(utils.moduleList()))
    parser.add_argument("--scanbuild",
                        help="Run scan-build on the code. Example: \
                              python3 build.py --scanbuild <agent|\
                              server|winagent>")
    parser.add_argument("--target",
                        help="Compile with a determinate target. Example: \
                              python3 build.py -r --target <agent|\
                              server|winagent>")

    args = parser.parse_args()
    if utils.argIsValid(arg=args.readytoreview):
        if utils.targetIsValid(arg=args.target):
            run_check.runReadyToReview(moduleName=args.readytoreview,
                                       target=args.target)
        else:
            run_check.runReadyToReview(moduleName=args.readytoreview)
    elif utils.argIsValid(arg=args.clean):
        build_tools.cleanLib(moduleName=args.clean)
    elif utils.argIsValid(arg=args.make):
        build_tools.makeLib(moduleName=args.make)
    elif utils.argIsValid(arg=args.tests):
        run_check.runTests(moduleName=args.tests)
    elif utils.argIsValid(arg=args.coverage):
        run_check.runCoverage(moduleName=args.coverage)
    elif utils.argIsValid(arg=args.valgrind):
        run_check.runValgrind(moduleName=args.valgrind)
    elif utils.argIsValid(arg=args.cppcheck):
        run_check.runCppCheck(moduleName=args.cppcheck)
    elif utils.argIsValid(arg=args.asan) and args.path:
        run_check.runASAN(moduleName=args.asan,
                          testToolConfig=args.path)
    elif utils.argIsValid(arg=args.scheck):
        run_check.runAStyleCheck(moduleName=args.scheck)
    elif utils.argIsValid(arg=args.sformat):
        run_check.runAStyleFormat(moduleName=args.sformat)
    elif utils.targetIsValid(arg=args.scanbuild):
        run_check.runScanBuild(targetName=args.scanbuild)
    elif utils.argIsValid(arg=args.deleteLogs):
        utils.deleteLogs(moduleName=args.deleteLogs)
    elif utils.argIsValid(arg=args.readytoreviewandclean):
        if utils.targetIsValid(arg=args.target):
            run_check.runReadyToReview(moduleName=args.readytoreviewandclean,
                                       clean=True,
                                       target=args.target)
        else:
            run_check.runReadyToReview(moduleName=args.readytoreviewandclean,
                                       clean=True)
    else:
        parser.print_help()


if __name__ == "__main__":
    processArgs()
