import sys
import argparse
from importlib.metadata import metadata

from shared.default_settings import Constants
from engine_archiver.cmds.activate import configure as configure_activate
from engine_archiver.cmds.deactivate import configure as configure_deactivate
from engine_archiver.cmds.status import configure as configure_status


def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-archiver')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    # Add socket path argument
    parser.add_argument('--api-socket', type=str, default=Constants.SOCKET_PATH,
                        help='Path to the Wazuh API socket')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')

    configure_activate(subparsers)
    configure_deactivate(subparsers)
    configure_status(subparsers)

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(vars(args))


if __name__ == '__main__':
    sys.exit(main())
