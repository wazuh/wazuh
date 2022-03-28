# Copyright (C) 2015, Wazuh Inc.
# All right reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#

import argparse
from ci import run_check

module_list = ['wazuh_modules/syscollector', 'shared_modules/dbsync', 'shared_modules/rsync', 'shared_modules/utils',
               'data_provider', 'syscheckd']

module_list_str = '|'.join(module_list)


class CommandLineParser:

    def _argIsValid(self, arg):
        """
        Checks if the argument being selected is a correct one.

        :param arg: Argument being selected in the command line.
        :return True is 'arg' is a correct one, False otherwise.
        """
        return arg in module_list

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
        parser = argparse.ArgumentParser()
        parser.add_argument("-r", "--readytoreview",
                            help=f'Run all the quality checks needed to create a PR. Example: python3 build.py -r <{module_list_str}>')
        parser.add_argument("-d", "--deleteLogs",
                            help=f'Clean log results. Example: python3 build.py -d <{module_list_str}>')
        parser.add_argument("-rc", "--readytoreviewandclean",
                            help=f'Run all the quality checks needed to create a PR and clean results. Example: python3 build.py '
                                  '-rc <{module_list_str}>')
        parser.add_argument(
            "-m", "--make", help=f'Compile the lib. Example: python3 build.py -m <{module_list_str}>')
        parser.add_argument(
            "-t", "--tests", help=f'Run tests (should be configured with TEST=on). Example: python3 build.py -t <{module_list_str}>')
        parser.add_argument(
            "-c", "--coverage", help=f'Collect tests coverage and generates report. Example: python3 build.py -c <{module_list_str}>')
        parser.add_argument(
            "-v", "--valgrind", help=f'Run valgrind on tests. Example: python3 build.py -v <{module_list_str}>')
        parser.add_argument(
            "--clean", help=f'Clean the lib. Example: python3 build.py --clean <{module_list_str}>')
        parser.add_argument(
            "--cppcheck", help=f'Run cppcheck on the code. Example: python3 build.py --cppcheck <{module_list_str}>')
        parser.add_argument(
            "--asan", help=f'Run ASAN on the code. Example: python3 build.py --asan <{module_list_str}>')
        parser.add_argument(
            "--scheck", help=f'Run AStyle on the code for checking purposes. Example: python3 build.py --scheck <{module_list_str}>')
        parser.add_argument(
            "--sformat", help=f'Run AStyle on the code formatting the needed files. Example: python3 build.py --sformat <{module_list_str}>')
        parser.add_argument(
            "--scanbuild", help="Run scan-build on the code. Example: python3 build.py --scanbuild <agent|server|winagent>")

        args = parser.parse_args()
        if self._argIsValid(args.readytoreview):
            run_check.runReadyToReview(args.readytoreview)
        elif self._argIsValid(args.clean):
            run_check.cleanLib(args.clean)
        elif self._argIsValid(args.make):
            run_check.makeLib(args.make)
        elif self._argIsValid(args.tests):
            run_check.runTests(args.tests)
        elif self._argIsValid(args.coverage):
            run_check.runCoverage(args.coverage)
        elif self._argIsValid(args.valgrind):
            run_check.runValgrind(args.valgrind)
        elif self._argIsValid(args.cppcheck):
            run_check.runCppCheck(args.cppcheck)
        elif self._argIsValid(args.asan):
            run_check.runASAN(args.asan)
        elif self._argIsValid(args.scheck):
            run_check.runAStyleCheck(args.scheck)
        elif self._argIsValid(args.sformat):
            run_check.runAStyleFormat(args.sformat)
        elif self._targetIsValid(args.scanbuild):
            run_check.runScanBuild(args.scanbuild)
        elif self._argIsValid(args.deleteLogs):
            run_check.deleteLogs(args.deleteLogs)
        elif self._argIsValid(args.readytoreviewandclean):
            run_check.runReadyToReview(args.readytoreviewandclean, True)
        else:
            parser.print_help()


if __name__ == "__main__":
    cmdLineParser = CommandLineParser()
    cmdLineParser.processArgs()
