import sys
import json

from engine_test.conf.store import ConfigDatabase
from shared.dumpers import dict_to_str_json, dict_to_str_yml


def run(args):

    try:
        # Get the configuration database
        db = ConfigDatabase(args['config_file'])

        # Get integration configuration
        iconf = db.get_integration(args['integration-name'])

        _, dump = iconf.dump_as_tuple()

        if args['json']:
            print(dict_to_str_json(dump))
        else:
            print(dict_to_str_yml(dump))
    except Exception as e:
        sys.exit(f"Error getting integration configuration: {e}")


def configure(subparsers):

    parser = subparsers.add_parser("get", help='Get integration configuration')
    parser.add_argument('-j', '--json', action='store_true',
                        help=f'Output in JSON format (default is YAML)', default=False)

    parser.add_argument('integration-name', type=str, help=f'Integration name')

    parser.set_defaults(func=run)
