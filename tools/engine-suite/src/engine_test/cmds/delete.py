import argparse
import sys

from engine_test.conf.integration import Formats, IntegrationConf
from engine_test.conf.store import ConfigDatabase


def run(args):

    try:
        # Get the configuration database
        db = ConfigDatabase(args['config_file'])

        # Remove integration configuration
        db.remove_integration(args['integration-name'])

    except Exception as e:
        sys.exit(f"Error deletting integration configuration: {e}")


def configure(subparsers):

    parser = subparsers.add_parser("delete", help='Delete integration configuration')
    parser.add_argument('integration-name', type=str, help=f'Integration name')

    parser.set_defaults(func=run)
