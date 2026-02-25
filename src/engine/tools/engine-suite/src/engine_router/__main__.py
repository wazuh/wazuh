import sys
import argparse
from importlib.metadata import metadata

from shared.default_settings import Constants
from engine_router.cmds.get import configure as configure_get
from engine_router.cmds.delete import configure as configure_delete
from engine_router.cmds.add import configure as configure_add
from engine_router.cmds.reload import configure as configure_reload
from engine_router.cmds.update import configure as configure_update

from engine_router.cmds.list import configure as configure_list
from engine_router.cmds.ingest import configure as configure_ingest


def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-router')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    # Add socket path argument
    parser.add_argument('--api-socket', type=str, default=Constants.SOCKET_PATH,
                        help='Path to the Wazuh API socket')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')

    # Routes
    configure_get(subparsers)
    configure_delete(subparsers)
    configure_add(subparsers)
    configure_reload(subparsers)
    configure_update(subparsers)

    # Table
    configure_list(subparsers)

    # Queue
    configure_ingest(subparsers)

    try:
        import argcomplete
        argcomplete.autocomplete(parser, always_complete_options=False)
    except ImportError:
        pass

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(vars(args))


if __name__ == '__main__':
    sys.exit(main())
