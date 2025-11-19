import sys
import argparse
from importlib.metadata import metadata

from shared.default_settings import Constants
from engine_ns.cmds.list import configure as configure_list
from engine_ns.cmds.create import configure as configure_create
from engine_ns.cmds.delete import configure as configure_delete


def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-ns')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    # Add socket path argument
    parser.add_argument('--api-socket', type=str, default=Constants.SOCKET_PATH,
                        help='Path to the Wazuh API socket')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')

    configure_create(subparsers)
    configure_delete(subparsers)
    configure_list(subparsers)

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(vars(args))


if __name__ == '__main__':
    sys.exit(main())
