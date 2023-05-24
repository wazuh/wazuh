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
                              -r <{}>".format(utils.moduleListStr()),
                        choices=utils.moduleList(),
                        metavar="")
    parser.add_argument("-d", "--readytoreviewandclean",
                        help="Run all the quality checks needed to \
                              create a PR and clean results. Example: \
                              python3 build.py -d <{}>"
                              .format(utils.moduleListStr()),
                        choices=utils.moduleList(),
                        metavar="")
    parser.add_argument("-m", "--make",
                        help="Compile the lib. Example: python3 build.py\
                              -m <{}>".format(utils.moduleListStr()),
                        choices=utils.moduleList(),
                        metavar="")
    parser.add_argument("-t", "--tests",
                        help="Run tests (should be configured with \
                              TEST=on). Example: python3 build.py -t\
                              <{}>".format(utils.moduleListStr()),
                        choices=utils.moduleList(),
                        metavar="")
    parser.add_argument("-c", "--coverage",
                        help="Collect tests coverage and generates\
                              report. Example: python3 build.py -c <{}>"
                              .format(utils.moduleListStr()),
                        choices=utils.moduleList(),
                        metavar="")
    parser.add_argument("-v", "--valgrind",
                        help="Run valgrind on tests. Example: python3 \
                              build.py -v <{}>".format(utils.moduleListStr()),
                        choices=utils.moduleList(),
                        metavar="")
    parser.add_argument("--clean",
                        help="Clean the lib. Example: python3 build.py \
                              --clean <{}>".format(utils.moduleListStr()),
                        choices=utils.moduleList(),
                        metavar="")
    parser.add_argument("--cppcheck",
                        help="Run cppcheck on the code. Example: python3 \
                              build.py --cppcheck <{}>"
                        .format(utils.moduleListStr()),
                        choices=utils.moduleList(),
                        metavar="")
    parser.add_argument("--asan",
                        help="Run ASAN on the code. Example: python3 \
                              build.py --asan <{}> --path /home/test"
                        .format(utils.moduleListStr()),
                        choices=utils.moduleList(),
                        metavar="")
    parser.add_argument("--path",
                        help="Add path to configure test tool to run ASAN\
                              on the code. Example: python3 build.py \
                              --asan <{}> --path /home/test"
                        .format(utils.moduleListStr()),
                        metavar="")
    parser.add_argument("--scheck",
                        help="Run AStyle on the code for checking \
                              purposes. Example: python3 build.py \
                              --scheck <{}>".format(utils.moduleListStr()),
                        metavar="")
    parser.add_argument("--sformat",
                        help="Run AStyle on the code formatting the \
                              needed files. Example: python3 build.py \
                              --sformat <{}>".format(utils.moduleListStr()),
                        metavar="")
    parser.add_argument("--scanbuild",
                        help="Run scan-build on the code. Example: \
                              python3 build.py --scanbuild <agent|\
                              server|winagent>",
                        choices=utils.targetList(),
                        metavar="")
    parser.add_argument("--target",
                        help="Compile with a determinate target. Example: \
                              python3 build.py -r data_provider --target <agent|\
                              server|winagent>",
                        choices=utils.targetList(),
                        metavar="")
    parser.add_argument("--deleteLogs",
                        help="Clean log results. Example: python3 build.py \
                              --deleteLogs <{}>".format(utils.moduleListStr()),
                        choices=utils.moduleList(),
                        metavar="")
    parser.add_argument("--cpus",
                        help="Number of processors to use in the compilation process. Example: \
                              python3 build.py -r data_provider --target agent --cpus 8",
                              metavar="")

    args = parser.parse_args()

    utils.initializeCpuCores()
    if args.cpus:
        utils.setCpuCores(args.cpus)

    if args.readytoreview:
        if args.target:
            run_check.runReadyToReview(moduleName=args.readytoreview,
                                       target=args.target)
        else:
            run_check.runReadyToReview(moduleName=args.readytoreview)
    elif args.clean:
        build_tools.cleanLib(moduleName=args.clean)
    elif args.make:
        build_tools.makeLib(moduleName=args.make)
    elif args.tests:
        run_check.runTests(moduleName=args.tests)
    elif args.coverage:
        run_check.runCoverage(moduleName=args.coverage)
    elif args.valgrind:
        run_check.runValgrind(moduleName=args.valgrind)
    elif args.cppcheck:
        run_check.runCppCheck(moduleName=args.cppcheck)
    elif args.asan and args.path:
        run_check.runASAN(moduleName=args.asan,
                          testToolConfig=utils.readJSONFile(jsonFilePath=args.path))
    elif args.scheck:
        run_check.runAStyleCheck(moduleName=args.scheck)
    elif args.sformat:
        run_check.runAStyleFormat(moduleName=args.sformat)
    elif args.scanbuild:
        run_check.runScanBuild(targetName=args.scanbuild)
    elif args.deleteLogs:
        utils.deleteLogs(moduleName=args.deleteLogs)
    elif args.readytoreviewandclean:
        if args.target:
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
