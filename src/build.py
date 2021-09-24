# Copyright (C) 2015-2021, Wazuh Inc.
# All right reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation
#

import argparse
from ci import utils

module_list = ['wazuh_modules/syscollector', 'shared_modules/dbsync', 'shared_modules/rsync', 'shared_modules/utils',
               'data_provider', 'syscheckd/db']

module_list_str = '|'.join(module_list)


class CommandLineParser:

    def _argIsValid(self, arg):
        """
        Checks if the argument being selected is a correct one.

        :param arg: Argument being selected in the command line.
        :return True is 'arg' is a correct one, False otherwise.
        """
        return arg in module_list

    def processArgs(self):
        """
        Process the command line arguments and executes the corresponding argument's utility.
        """
        action = False
        parser = argparse.ArgumentParser()
        parser.add_argument("-r", "--readytoreview",
                            help=f'Run all the quality checks needed to create a PR. Example: python3 build.py -r <{module_list_str}>')
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

        args = parser.parse_args()
        if self._argIsValid(args.readytoreview):
            utils.runReadyToReview(args.readytoreview)
            action = True
        else:
            if self._argIsValid(args.clean):
                utils.cleanLib(args.clean)
                action = True
            if self._argIsValid(args.make):
                utils.makeLib(args.make)
                action = True
            if self._argIsValid(args.tests):
                utils.runTests(args.tests)
                action = True
            if self._argIsValid(args.coverage):
                utils.runCoverage(args.coverage)
                action = True
            if self._argIsValid(args.valgrind):
                utils.runValgrind(args.valgrind)
                action = True
            if self._argIsValid(args.cppcheck):
                utils.runCppCheck(args.cppcheck)
                action = True
            if self._argIsValid(args.asan):
                utils.runASAN(args.asan)
                action = True
            if self._argIsValid(args.scheck):
                utils.runAStyleCheck(args.scheck)
                action = True
            if self._argIsValid(args.sformat):
                utils.runAStyleFormat(args.sformat)
                action = True
            if not action:
                parser.print_help()


if __name__ == "__main__":
    cmdLineParser = CommandLineParser()
    cmdLineParser.processArgs()
