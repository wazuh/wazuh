#!/usr/bin/env python3
from health_test.core import run as test_run
from health_test.validate_custom_field_indexing import run as validate_custom_field_indexing_run
from health_test.validate_event_indexing import run as validate_event_indexing_run
import sys
from argparse import ArgumentParser, Namespace

from health_test.metadata_validate import run as metadata_validate_run
from health_test.schema_validate import run as schema_validate_run
from health_test.mandatory_mapping_validate import run as mandatory_mapping_validate_run
from health_test.event_processing import run as event_processing_run
from health_test.initial_state import run as init_run
from health_test.load_decoders import run as load_decoders_run
from health_test.load_rules import run as load_rules_run
from health_test.assets_validate import run as assets_validate_run
from health_test.decoder_mapping_validate import run as decoder_mapping_validate_run
from health_test.rule_mapping_validate import run as rule_mapping_validate_run
from health_test.validate_successful_assets import run as validate_successful_assets_run


def parse_args() -> Namespace:
    parser = ArgumentParser(prog='engine-health-test')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')

    # Static subcommand group
    static_parser = subparsers.add_parser(
        'static', help='Static tests related to metadata, schema, mandatory mapping, and event processing')
    static_subparsers = static_parser.add_subparsers(
        title='static tests', required=True, dest='static_test')

    static_parser.add_argument('-r', '--ruleset',
                               help='Specify the path to the ruleset directory', type=str, required=True)

    # metadata validate subcommand
    metadata_validate_parser = static_subparsers.add_parser(
        'metadata_validate',     help=(
            'Validate metadata field in all integrations, decoder or specifies rule folder. '
            'If you do not specify a specific target, all assets will be validated. '
            'However, if you specify the target, only one is accepted.'))
    metadata_validate_parser.add_argument('--integration', help='Specify integration name', required=False)
    metadata_validate_parser.add_argument('--decoder', help='Specify decoder name', required=False)
    metadata_validate_parser.add_argument('--rule_folder', help='Specify rule folder name', required=False)
    metadata_validate_parser.set_defaults(func=metadata_validate_run)

    # schema validate subcommand
    schema_validate_parser = static_subparsers.add_parser(
        'schema_validate', help='Validate schema in integrations.')
    schema_validate_parser.add_argument('--integration', help='Specify integration name', required=False)
    schema_validate_parser.add_argument('--rule_folder', help='Specify rule folder name', required=False)
    schema_validate_parser.set_defaults(func=schema_validate_run)

    # mandatory mapping validate subcommand
    mandatory_mapping_validate_parser = static_subparsers.add_parser(
        'mandatory_mapping_validate',
        help='Validates that mandatory mapping fields are present after the decoding stage')
    mandatory_mapping_validate_parser.add_argument('--integration', help='Specify integration name', required=False)
    mandatory_mapping_validate_parser.add_argument('--rule_folder', help='Specify rule folder name', required=False)
    mandatory_mapping_validate_parser.set_defaults(func=mandatory_mapping_validate_run)

    # event processing subcommand
    event_processing_validate_parser = static_subparsers.add_parser(
        'event_processing_validate', help='Validates that each asset in the ruleset has processed at least one event')
    event_processing_validate_parser.set_defaults(func=event_processing_run)

    # Dynamic subcommand group
    dynamic_parser = subparsers.add_parser(
        'dynamic', help='Dynamic tests including initialization, rule loading, integration, and validation')
    dynamic_subparsers = dynamic_parser.add_subparsers(
        title='dynamic tests', required=True, dest='dynamic_test')

    dynamic_parser.add_argument('-e', '--environment',
                                help='Environment to run the tests in', type=str, required=True)

    # init subcommand
    init_parser = dynamic_subparsers.add_parser(
        'init', help='Initialize the test environment')
    init_parser.add_argument('-r', '--ruleset',
                             help='Specify the path to the ruleset directory', required=True)
    init_parser.add_argument(
        '-t', '--test-dir', help='Specify the path to the test directory', required=True)
    init_parser.add_argument(
        '--stop-on-warning', action='store_true',
        help='Stop the initialization process if a warning is encountered when creating the policy')
    init_parser.set_defaults(func=init_run)

    # load decoders subcommand
    load_decoders_parser = dynamic_subparsers.add_parser(
        'load_decoders', help='Create the filters, load the integrations and add the assets to the policy')
    load_decoders_parser.set_defaults(func=load_decoders_run)

    # load rules subcommand
    load_rules_parser = dynamic_subparsers.add_parser(
        'load_rules', help='Create the rules and add it to the policy')
    load_rules_parser.set_defaults(func=load_rules_run)

    # assets validate subcommand
    assets_validate = dynamic_subparsers.add_parser(
        'assets_validate', help=(
            'Validates integrations, decoders or rules '
            'If you do not specify a specific target, all assets will be validated. '
            'However, if you specify the target, only one is accepted.'))
    assets_validate.add_argument('--integration', help='Specify integration name', required=False)
    assets_validate.add_argument('--decoder', help='Specify decoder name', required=False)
    assets_validate.add_argument('--rule_folder', help='Specify the name of the rule folder to test', required=False)
    assets_validate.set_defaults(func=assets_validate_run)

    # successful assets validate subcommand
    validate_successful_assets_parser = dynamic_subparsers.add_parser(
        'validate_successful_assets', help=(
            'Verifies in the trace that the decoders that were successful are added to wazuh.decoders and that the successful rules are added to wazuh.rules'
            'If you do not specify a specific argument, an error will be thrown. '
            'However, if you do specify the argument, only one is accepted.'))
    validate_successful_assets_parser.add_argument(
        '--integration', help='Specify the name of the integration to test.', default=None)
    validate_successful_assets_parser.add_argument(
        '--rule_folder', help='Specify the name of the rule folder to test.', default=None)
    validate_successful_assets_parser.add_argument(
        '--target',
        help='Specify the asset type (decoder or rule). If it is a decoder, the tests are carried out for all decoders. The same for the rules.',
        required=False)
    validate_successful_assets_parser.add_argument(
        '--skip', help='Skip the tests with the specified name', default=None)
    validate_successful_assets_parser.set_defaults(func=validate_successful_assets_run)

    # decoder mapping validate subcommand
    validate_decoder_mapping_parser = dynamic_subparsers.add_parser(
        'validate_decoder_mapping', help='Verifies that only certain fields are mapped in the decoders.')
    validate_decoder_mapping_parser.add_argument(
        '--integration',
        help='Specify the name of the integration to test, if not specified all integration will be tested',
        default=None)
    validate_decoder_mapping_parser.add_argument(
        '--skip', help='Skip the tests with the specified name', default=None)
    validate_decoder_mapping_parser.set_defaults(func=decoder_mapping_validate_run)

    # rule mapping validate subcommand
    validate_rule_mapping_parser = dynamic_subparsers.add_parser(
        'validate_rule_mapping', help='Verifies that only certain fields are mapped in the rules.')
    validate_rule_mapping_parser.add_argument(
        '--rule_folder',
        help='Specify the name of the rule folder to test, if not specified all rules folder will be tested',
        default=None)
    validate_rule_mapping_parser.add_argument(
        '--skip', help='Skip the tests with the specified name', default=None)
    validate_rule_mapping_parser.set_defaults(func=rule_mapping_validate_run)

    # validate event indexing subcommand
    validate_event_indexing_parser = dynamic_subparsers.add_parser(
        'validate_event_indexing', help=(
            'Creates an opensearch instance along with an index. Ingests different events to the engine and compares '
            'the output with the document searched by hash in the index an expected one. '
            'If you do not specify a specific argument, an error will be thrown. '
            'However, if you specify the argumnet, only one is accepted.'))
    validate_event_indexing_parser.add_argument(
        '--integration', help='Specify the name of the integration to test.', default=None)
    validate_event_indexing_parser.add_argument(
        '--rule_folder', help='Specify the name of the rule folder to test', default=None)
    validate_event_indexing_parser.add_argument(
        '--skip', help='Skip the tests with the specified name', required=False)
    validate_event_indexing_parser.add_argument(
        '--target',
        help='Specify the asset type (decoder or rule). If it is a decoder, the tests are carried out for all decoders. The same for the rules.',
        required=False)
    validate_event_indexing_parser.set_defaults(func=validate_event_indexing_run)

    # validate custom field indexing
    validate_custom_field_indexing_parser = dynamic_subparsers.add_parser(
        'validate_custom_field_indexing', help=(
            'Creates an opensearch instance along with an index. It ingests different events to the engine and extracts all the custom fields. '
            'It then verifies that each of the custom fields are present in the opensearch index.'
            'If you do not specify a specific argument, an error will be raised. '
            'However, if you specify the argument, only one is accepted.'))
    validate_custom_field_indexing_parser.add_argument(
        '--integration', help='Specify the name of the integration to test.', default=None)
    validate_custom_field_indexing_parser.add_argument(
        '--rule_folder', help='Specify the name of the rule folder to test', default=None)
    validate_custom_field_indexing_parser.add_argument(
        '--skip', help='Skip the tests with the specified name', required=False)
    validate_custom_field_indexing_parser.add_argument(
        '--target',
        help='Specify the asset type (decoder or rule). If it is a decoder, the tests are carried out for all decoders. The same for the rules.',
        required=False)
    validate_custom_field_indexing_parser.set_defaults(func=validate_custom_field_indexing_run)

    # test subcommand
    test_parser = dynamic_subparsers.add_parser(
        'run', help=(
            'Ingests different events to the engine and compares the output with an expected one. '
            'If you do not specify a specific argument, an error will be thrown. '
            'However, if you specify the argumnet, only one is accepted.'))
    test_parser.add_argument(
        '--integration', help='Specify the name of the integration to test.', default=None)
    test_parser.add_argument(
        '--rule_folder', help='Specify the name of the rule folder to test', default=None)
    test_parser.add_argument(
        '--skip', help='Skip the tests with the specified name', required=False)
    test_parser.add_argument(
        '--target',
        help='Specify the asset type (decoder or rule). If it is a decoder, the tests are carried out for all decoders. The same for the rules.',
        required=False)
    test_parser.set_defaults(func=test_run)

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(vars(args))


if __name__ == '__main__':
    sys.exit(main())
