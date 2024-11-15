import sys
import argparse
from importlib.metadata import metadata

import shared.resource_handler as rs
from shared.default_settings import Constants as DefaultSettings
from engine_catalog.cmds.delete import configure as configure_delete
from engine_catalog.cmds.get import configure as configure_get
from engine_catalog.cmds.update import configure as configure_update
from engine_catalog.cmds.create import configure as configure_create
from engine_catalog.cmds.validate import configure as configure_validate
from engine_catalog.cmds.load import configure as configure_load


def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-catalog')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    # Add socket path argument
    parser.add_argument('--api-socket', type=str, default=DefaultSettings.SOCKET_PATH,
                        help='Path to the Wazuh API socket')
    parser.add_argument('-n', '--namespace', type=str, default=DefaultSettings.DEFAULT_NS,
                        help='Namespace to use for the catalog')

    # Add parser for --format, only enum json or yml
    parser.add_argument('--format', type=str, default='yml', choices=['json', 'yml', 'yaml'],
                        help='Input/Output format')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')

    configure_delete(subparsers)
    configure_get(subparsers)
    configure_update(subparsers)
    configure_create(subparsers)
    configure_validate(subparsers)
    configure_load(subparsers)

    return parser.parse_args()


def main():
    args = parse_args()
    resource_handler = rs.ResourceHandler()
    args.func(vars(args), resource_handler)


if __name__ == '__main__':
    sys.exit(main())
