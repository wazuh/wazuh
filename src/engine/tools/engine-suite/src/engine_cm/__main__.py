import sys
import argparse
from importlib.metadata import metadata

from shared.default_settings import Constants as DefaultSettings
from engine_cm.cmds.list import configure as configure_list
from engine_cm.cmds.upsert import configure as configure_upsert
from engine_cm.cmds.delete import configure as configure_delete
from engine_cm.cmds.get import configure as configure_get
from engine_cm.cmds.policy_upsert import configure as configure_policy_upsert
from engine_cm.cmds.policy_delete import configure as configure_policy_delete


def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-cm')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    # Add socket path argument
    parser.add_argument('--api-socket', type=str, default=DefaultSettings.SOCKET_PATH,
                        help='Path to the Wazuh API socket')
    parser.add_argument('-n', '--space', type=str, default=DefaultSettings.DEFAULT_NS,
                        help='Namespace to use for the crud')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')

    configure_upsert(subparsers)
    configure_delete(subparsers)
    configure_get(subparsers)
    configure_list(subparsers)
    configure_policy_upsert(subparsers)
    configure_policy_delete(subparsers)

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(vars(args))


if __name__ == '__main__':
    sys.exit(main())
