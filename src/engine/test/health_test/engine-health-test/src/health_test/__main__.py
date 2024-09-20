#!/usr/bin/env python3
import sys
from argparse import ArgumentParser, Namespace

from health_test.metadata_validate import run as metadata_validate_run
from health_test.schema_validate import run as schema_validate_run
from health_test.mapping_validate import run as mapping_validate_run
from health_test.initial_state import run as init_run
from health_test.load_ruleset import run as load_ruleset_run
from health_test.integration_validate import run as integration_validate_run
from health_test.health_test import run as test_run


def parse_args() -> Namespace:
    parser = ArgumentParser(prog='engine-health-test')
    parser.add_argument('-e', '--environment',
                        help='Environment to run the tests in', type=str, required=False)

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')

    # metadata validate subcommand
    metadata_validate_parser = subparsers.add_parser(
        'metadata_validate', help='Validate metadata field in all integrations or specifies assets.')
    metadata_validate_parser.add_argument('-r', '--ruleset',
                            help='Specify the path to the ruleset directory', required=True)
    metadata_validate_parser.add_argument('--integration', help='Specify integration name', required=False)
    metadata_validate_parser.add_argument('--asset', help='Specify asset name', required=False)
    metadata_validate_parser.set_defaults(func=metadata_validate_run)

    # schema validate subcommand
    schema_validate_parser = subparsers.add_parser(
        'schema_validate', help='Validate schema in integrations.')
    schema_validate_parser.add_argument('-r', '--ruleset',
                            help='Specify the path to the ruleset directory', required=True)
    schema_validate_parser.add_argument('--integration', help='Specify integration name', required=False)
    schema_validate_parser.set_defaults(func=schema_validate_run)

    # mapping validate subcommand
    mapping_validate_parser = subparsers.add_parser(
        'mapping_validate', help='Validates that mandatory mapping fields are present after the decoding stage')
    mapping_validate_parser.add_argument('-r', '--ruleset',
                            help='Specify the path to the ruleset directory', required=True)
    mapping_validate_parser.add_argument('--integration', help='Specify integration name', required=False)
    mapping_validate_parser.set_defaults(func=mapping_validate_run)

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

    # integration validate subcommand
    integration_validate = subparsers.add_parser(
        'integration_validate', help='Validate integrations or specifies assets.')
    integration_validate.add_argument('--integration', help='Specify integration name', required=False)
    integration_validate.add_argument('--asset', help='Specify asset name', required=False)
    integration_validate.set_defaults(func=integration_validate_run)

    # load ruleset
    load_ruleset_parser = subparsers.add_parser(
        'load_ruleset', help='Create the filters, load the integrations and add the assets to the policy')
    load_ruleset_parser.set_defaults(func=load_ruleset_run)

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
