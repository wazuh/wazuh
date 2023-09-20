from enum import Enum
import sys
import argparse
from importlib.metadata import metadata
from engine_test.cmds.run import configure as configure_parser_run
from engine_test.cmds.add import configure as configure_parser_add
from engine_test.cmds.get import configure as configure_parser_get
from engine_test.cmds.list import configure as configure_parser_list

class Defaults(Enum):
    AGENT_ID = "001"
    AGENT_NAME = "wazuh-agent-1"
    AGENT_IP = "any"
    OUTPUT_FILE = '/tmp/engine_test.out'

def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-test')

    parser.add_argument('-i', '--agent-id', help=f'Agent ID for event filling',
                        type=str, default=Defaults.AGENT_ID.value, dest='agent_id')

    parser.add_argument('-n', '--agent-name', help=f'Agent name for events filling',
                        type=str, default=Defaults.AGENT_NAME.value, dest='agent_name')

    parser.add_argument('-a', '--agent-ip', help=f'Agent ip address for events filling',
                        type=str, default=Defaults.AGENT_IP.value, dest='agent_ip')

    parser.add_argument('-O', '--origin', help=f'Origin of the integration',
                        type=str, dest='origin')

    parser.add_argument('-o', '--output', help=f'Output file where the events will be stored, if empty events wont be saved',
                        type=str, default=Defaults.OUTPUT_FILE.value, dest='output_file')

    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')
    parser.add_argument(
        '-v', '--verbose', help=f'Print traceback on error messages',
                        action='store_true', dest='verbose')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(title='subcommands', required=True, dest='subcommand')

    configure_parser_run(subparsers)
    configure_parser_add(subparsers)
    configure_parser_get(subparsers)
    configure_parser_list(subparsers)

    return parser.parse_args()

def main():
    args = parse_args()

    if not args.verbose:
        sys.tracebacklimit = 0

    args.func(vars(args))

if __name__ == '__main__':
    sys.exit(main())
