import sys
import argparse
from importlib.metadata import metadata

from shared.default_settings import Constants
from engine_geo.cmds.add import configure as configure_add
from engine_geo.cmds.delete import configure as configure_delete
from engine_geo.cmds.list import configure as configure_list
from engine_geo.cmds.upsert import configure as configure_upsert

def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-geo')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    # Add socket path argument
    parser.add_argument('--api-socket', type=str, default=Constants.SOCKET_PATH,
                        help='Path to the Wazuh API socket')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')

    configure_add(subparsers)
    configure_delete(subparsers)
    configure_list(subparsers)
    configure_upsert(subparsers)


    return parser.parse_args()


def main():
    args = parse_args()
    args.func(vars(args))


if __name__ == '__main__':
    sys.exit(main())
