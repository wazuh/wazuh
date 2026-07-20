import argparse
from shared.default_settings import Constants as DefaultSettings
from engine_test.cmds.session_list import configure as configure_list
from engine_test.cmds.session_get import configure as configure_get
from engine_test.cmds.session_add import configure as configure_add
from engine_test.cmds.session_delete import configure as configure_delete
from engine_test.cmds.session_delete_all import configure as configure_delete_all
from engine_test.cmds.session_reload import configure as configure_reload


def configure(subparsers):

    # add session subcommand
    session_parser = subparsers.add_parser('session', help='Session manager')

    session_parser.add_argument('--api-socket', type=str, default=DefaultSettings.SOCKET_PATH,
                                help='Path to the Wazuh API socket (default: %(default)s)')

    # add session subparsers
    session_subparsers = session_parser.add_subparsers(
        title='session commands', required=True, dest='session_command')
    configure_list(session_subparsers)
    configure_get(session_subparsers)
    configure_add(session_subparsers)
    configure_delete(session_subparsers)
    configure_reload(session_subparsers)
    configure_delete_all(session_subparsers)


def run(args):
    args.func(vars(args))
