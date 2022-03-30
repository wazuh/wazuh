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
        None

    Returns:
        None
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

    args = parser.parse_args()
    if utils.argIsValid(args.readytoreview):
        run_check.runReadyToReview(args.readytoreview)
    elif utils.argIsValid(args.clean):
        build_tools.cleanLib(args.clean)
    elif utils.argIsValid(args.make):
        build_tools.makeLib(args.make)
    elif utils.argIsValid(args.tests):
        run_check.runTests(args.tests)
    elif utils.argIsValid(args.coverage):
        run_check.runCoverage(args.coverage)
    elif utils.argIsValid(args.valgrind):
        run_check.runValgrind(args.valgrind)
    elif utils.argIsValid(args.cppcheck):
        run_check.runCppCheck(args.cppcheck)
    elif utils.argIsValid(args.asan) and args.path:
        run_check.runASAN(args.asan, args.path)
    elif utils.argIsValid(args.scheck):
        run_check.runAStyleCheck(args.scheck)
    elif utils.argIsValid(args.sformat):
        run_check.runAStyleFormat(args.sformat)
    elif utils.targetIsValid(args.scanbuild):
        run_check.runScanBuild(args.scanbuild)
    elif utils.argIsValid(args.deleteLogs):
        utils.deleteLogs(args.deleteLogs)
    elif utils.argIsValid(args.readytoreviewandclean):
        run_check.runReadyToReview(args.readytoreviewandclean, True)
    else:
        parser.print_help()


if __name__ == "__main__":
    processArgs()
