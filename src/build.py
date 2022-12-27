# Copyright (C) 2015, Wazuh Inc.
# All right reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#

import argparse
from ci import utils

target_list = ['syscollector', 'dbsync', 'rsync','utils_unit_test', 'sysinfo']

class CommandLineParser:

    def _argIsCmakeLibTargetValid(self, arg):
        """
        Checks if the argument being selected is a correct one.

        :param arg: Argument being selected in the command line.
        :return True is 'arg' is a correct one, False otherwise.
        """
        return arg in target_list

    def _targetIsValid(self, arg):
        """
        Checks if the argument being selected is a correct one.

        :param arg: Argument being selected in the command line.
        :return True is 'arg' is a correct one, False otherwise.
        """
        validArguments = ['agent',
                          'server',
                          'winagent']
        return arg in validArguments

    def processArgs(self):
        """
        Process the command line arguments and executes the corresponding argument's utility.
        """
        action = False
        parser = argparse.ArgumentParser()
        parser.add_argument("-r", "--readytoreview", help="Run all the quality checks needed to create a PR. Example: python3 build.py -r <sysinfo|dbsync|rsync|utils_unit_test|syscollector>")
        parser.add_argument("-m", "--make", help="Compile the lib. Example: python3 build.py -m  <sysinfo|dbsync|rsync|utils_unit_test|syscollector>")
        parser.add_argument("-t", "--tests", help="Run tests (should be configured with TEST=on). Example: python3 build.py -t  <sysinfo|dbsync|rsync|utils_unit_test|syscollector>")
        parser.add_argument("-c", "--coverage", help="Collect tests coverage and generates report. Example: python3 build.py -c  <sysinfo|dbsync|rsync|utils_unit_test|syscollector>")
        parser.add_argument("-v", "--valgrind", help="Run valgrind on tests. Example: python3 build.py -v  <sysinfo|dbsync|rsync|utils_unit_test|syscollector>")
        parser.add_argument("--clean", help="Clean the lib. Example: python3 build.py --clean  <sysinfo|dbsync|rsync|utils_unit_test|syscollector>")
        parser.add_argument("--cppcheck", help="Run cppcheck on the code. Example: python3 build.py --cppcheck  <sysinfo|dbsync|rsync|utils_unit_test|syscollector>")
        parser.add_argument("--asan", help="Run ASAN on the code. Example: python3 build.py --asan  <sysinfo|dbsync|rsync|utils_unit_test|syscollector>")
        parser.add_argument("--scheck", help="Run AStyle on the code for checking purposes. Example: python3 build.py --scheck  <sysinfo|dbsync|rsync|utils_unit_test|syscollector>")
        parser.add_argument("--sformat", help="Run AStyle on the code formatting the needed files. Example: python3 build.py --sformat  <sysinfo|dbsync|rsync|utils_unit_test|syscollector>")
        parser.add_argument("--scanbuild", help="Run scan-build on the code. Example: python3 build.py --scanbuild <agent|server|winagent>")

        args = parser.parse_args()
        if self._argIsCmakeLibTargetValid(args.readytoreview):
            utils.runReadyToReview(args.readytoreview)
            action = True
        else:
            if self._argIsCmakeLibTargetValid(args.clean):
                utils.cleanLib(args.clean)
                action = True
            if self._argIsCmakeLibTargetValid(args.make):
                utils.makeAllLib(args.make)
                action = True
            if self._argIsCmakeLibTargetValid(args.tests):
                utils.runTests(args.tests)
                action = True
            if self._argIsCmakeLibTargetValid(args.coverage):
                utils.runCoverage(args.coverage)
                action = True
            if self._argIsCmakeLibTargetValid(args.valgrind):
                utils.runValgrind(args.valgrind)
                action = True
            if self._argIsCmakeLibTargetValid(args.cppcheck):
                utils.runCppCheck(args.cppcheck)
                action = True
            if self._argIsCmakeLibTargetValid(args.asan):
                utils.runASAN(args.asan)
                action = True
            if self._argIsCmakeLibTargetValid(args.scheck):
                utils.runAStyleCheck(args.scheck)
                action = True
            if self._argIsCmakeLibTargetValid(args.sformat):
                utils.runAStyleFormat(args.sformat)
                action = True
            if self._targetIsValid(args.scanbuild):
                utils.runScanBuild(args.scanbuild)
                action = True
            if not action:
                parser.print_help()


if __name__ == "__main__":
    cmdLineParser = CommandLineParser()
    cmdLineParser.processArgs()
