#!/usr/bin/env python3
import sys
from argparse import ArgumentParser, Namespace

from integration_test.initial_state import run as init_run
from integration_test.core import run as test_run


def parse_args() -> Namespace:
    parser = ArgumentParser(prog='engine-it')
    parser.add_argument('-e', '--environment',
                        help='Environment to run the tests in', type=str, required=True)
    parser.add_argument('-t', '--test-dir',
                        help='Specify the path to the tests directory', required=True)

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')

    # init subcommand
    init_parser = subparsers.add_parser(
        'init', help='Initialize the test environment')

    init_parser.set_defaults(func=init_run)

    # test subcommand
    test_parser = subparsers.add_parser(
        'run', help='Run the integration tests')
    test_parser.add_argument(
        '-f', '--feature', help='Feature file to run (default: all features)', default=None)

    test_parser.set_defaults(func=test_run)

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(vars(args))


if __name__ == '__main__':
    sys.exit(main())
