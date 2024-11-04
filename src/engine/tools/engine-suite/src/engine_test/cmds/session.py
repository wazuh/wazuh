import argparse
from shared.default_settings import Constants as DefaultSettings
from engine_test.cmds.session_list import configure as configure_list


def configure(subparsers):

    # add session subcommand
    session_parser = subparsers.add_parser('session', help='Session commands')

    session_parser.add_argument('--api-socket', type=str, default=DefaultSettings.SOCKET_PATH,
                                help='Path to the Wazuh API socket (default: %(default)s)')

    # add session subparsers
    session_subparsers = session_parser.add_subparsers(title='session commands', required=True, dest='session_command')
    configure_list(session_subparsers)


def run(args):
    args.func(vars(args))
