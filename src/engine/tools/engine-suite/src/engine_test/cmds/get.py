import sys, json

from engine_test.conf.store import ConfigDatabase

def run(args):

    try:
        # Get the configuration database
        db = ConfigDatabase(args['config_file'])

        # Get integration configuration
        iconf = db.get_integration(args['integration-name'])

        _, dump = iconf.dump_as_tuple()

        # TODO Use the print yml o json if -j is passed, print shared cli
        print(json.dumps(dump, indent=4, separators=(',', ': ')))
    except Exception as e:
        sys.exit(f"Error getting integration configuration: {e}")


def configure(subparsers):

    parser = subparsers.add_parser("get", help='Get integration configuration')
    parser.add_argument('-j', '--json', action='store_true', help=f'Output in JSON format (default is YAML)')

    parser.add_argument('integration-name', type=str, help=f'Integration name')

    parser.set_defaults(func=run)
