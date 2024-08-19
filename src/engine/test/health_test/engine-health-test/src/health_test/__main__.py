#!/usr/bin/env python3
import sys
from argparse import ArgumentParser, Namespace

from health_test.initial_state import run as init_run
from health_test.health_test import run as test_run


def parse_args() -> Namespace:
    parser = ArgumentParser(prog='engine-health-test')
    parser.add_argument('-e', '--environment',
                        help='Environment to run the tests in', type=str, required=True)

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')

    # init subcommand
    init_parser = subparsers.add_parser(
        'init', help='Initialize the test environment')
    init_parser.add_argument(
        '-b', '--binary', help='Specify the path to the engine binary', required=True)
    init_parser.add_argument('-r', '--ruleset',
                             help='Specify the path to the ruleset directory', required=True)
    init_parser.add_argument(
        '-t', '--test-dir', help='Specify the path to the test directory', required=True)
    init_parser.add_argument('--stop-on-warning', action='store_true',
                             help='Stop the initialization process if a warning is encountered when creating the policy')
    init_parser.set_defaults(func=init_run)

    # test subcommand
    test_parser = subparsers.add_parser(
        'run', help='Run the tests')
    test_parser.add_argument(
        '-i', '--integration', help='Specify the name of the integration to test, if not specified all integrations will be tested', default=None)
    test_parser.add_argument(
        '--skip', help='Skip the tests with the specified name', default=None)
    test_parser.set_defaults(func=test_run)

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(vars(args))


if __name__ == '__main__':
    sys.exit(main())
