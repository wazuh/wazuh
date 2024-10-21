import sys
import argparse
from importlib.metadata import metadata

from shared.default_settings import Constants
from engine_policy.cmds.create import configure as configure_create
from engine_policy.cmds.delete import configure as configure_delete
from engine_policy.cmds.get import configure as configure_get
from engine_policy.cmds.list import configure as configure_list
from engine_policy.cmds.asset_add import configure as configure_asset_add
from engine_policy.cmds.asset_delete import configure as configure_asset_remove
from engine_policy.cmds.asset_list import configure as configure_asset_list
from engine_policy.cmds.asset_clean import configure as configure_asset_clean
from engine_policy.cmds.parent_set import configure as configure_default_parent_set
from engine_policy.cmds.parent_remove import configure as configure_default_parent_remove
from engine_policy.cmds.namespace_get import configure as configure_namespace_get


def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-policy')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    # Add socket path argument
    parser.add_argument('--api-socket', type=str, default=Constants.SOCKET_PATH,
                        help='Path to the Wazuh API socket')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')

    # Store
    configure_create(subparsers)
    configure_delete(subparsers)
    configure_get(subparsers)
    # Policies
    configure_list(subparsers)
    # Assets
    configure_asset_add(subparsers)
    configure_asset_remove(subparsers)
    configure_asset_list(subparsers)
    configure_asset_clean(subparsers)
    # Default parent
    configure_default_parent_set(subparsers)
    configure_default_parent_remove(subparsers)
    # Namespaces
    configure_namespace_get(subparsers)


    return parser.parse_args()


def main():
    args = parse_args()
    args.func(vars(args))


if __name__ == '__main__':
    sys.exit(main())
