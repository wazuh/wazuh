import sys
import argparse
from importlib.metadata import metadata

from shared.default_settings import Constants
from engine_kvdb.cmds.manager_list import configure as configure_manager_list
from engine_kvdb.cmds.manager_create import configure as configure_manager_create
from engine_kvdb.cmds.manager_delete import configure as configure_manager_delete
from engine_kvdb.cmds.manager_dump import configure as configure_manager_dump
from engine_kvdb.cmds.db_get import configure as configure_get
from engine_kvdb.cmds.db_search import configure as configure_search
from engine_kvdb.cmds.db_remove import configure as configure_remove
from engine_kvdb.cmds.db_upsert import configure as configure_upsert



def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-kvdb')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    # Add socket path argument
    parser.add_argument('--api-socket', type=str, default=Constants.SOCKET_PATH,
                        help='Path to the Wazuh API socket')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')

    configure_manager_list(subparsers)
    configure_manager_create(subparsers)
    configure_manager_delete(subparsers)
    configure_manager_dump(subparsers)
    configure_get(subparsers)
    configure_search(subparsers)
    configure_remove(subparsers)
    configure_upsert(subparsers)

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(vars(args))


if __name__ == '__main__':
    sys.exit(main())
