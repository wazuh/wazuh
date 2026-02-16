import sys
import argparse
from importlib.metadata import metadata

from shared.default_settings import Constants as DefaultSettings
from engine_public.cmds.cm.policy_validate import configure as configure_policy_validate
from engine_public.cmds.cm.validate import configure as configure_validate
from engine_public.cmds.cm.logtest_cleanup import configure as configure_logtest_cleanup

def parse_args():
    meta = metadata('engine-suite')

    # Root parser
    parser = argparse.ArgumentParser(prog='engine-public')
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {meta.get("Version")}'
    )

    # Global argument: API socket
    parser.add_argument(
        '--api-socket',
        type=str,
        default=DefaultSettings.SOCKET_PATH,
        help='Path to the Wazuh API socket'
    )

    # Top-level subcommands (cm / ns)
    # dest is required because of https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands',
        required=True,
        dest='subcommand'
    )

    # ==========================================================
    # CM commands (operate INSIDE a namespace → require --space)
    # ==========================================================
    cm_parser = subparsers.add_parser(
        'cm',
        help='Content Manager operations'
    )

    cm_subparsers = cm_parser.add_subparsers(
        title='cm commands',
        required=True,
        dest='cm_command'
    )

    configure_policy_validate(cm_subparsers)
    configure_validate(cm_subparsers)
    configure_logtest_cleanup(cm_subparsers)

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
