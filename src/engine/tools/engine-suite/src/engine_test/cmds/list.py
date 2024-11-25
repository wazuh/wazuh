import argparse
import sys, json

from engine_test.conf.integration import Formats, IntegrationConf
from engine_test.conf.store import ConfigDatabase

def run(args):

    try:
        # Get the configuration database
        db = ConfigDatabase(args['config_file'])

        # Get all integration from the database
        iconfArray : dict[str, IntegrationConf] = db.get_all_integrations()


        # if detailed output is requested
        dump = {}
        if args['detailed']:
            for name, iconf in iconfArray.items():
                name, data = iconf.dump_as_tuple()
                dump[name] = data
        else:
            dump : list[str] = list(iconfArray.keys())


        # TODO Use the print yml o json if -j is passed, print shared cli
        print(json.dumps(dump, indent=4, separators=(',', ': ')))
    except Exception as e:
        sys.exit(f"Error listing integration configurations: {e}")


def configure(subparsers):

    parser = subparsers.add_parser("list", help='List integration configurations')
    parser.add_argument('-d', '--detailed', action='store_true', help=f'Detailed output')
    parser.add_argument('-j', '--json', action='store_true', help=f'Output in JSON format (default is YAML)')
    parser.set_defaults(func=run)
