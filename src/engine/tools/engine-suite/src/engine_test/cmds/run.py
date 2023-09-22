from enum import Enum
from engine_test.integration import Integration

class Defaults(Enum):
    AGENT_ID = "001"
    AGENT_NAME = "wazuh-agent-1"
    AGENT_IP = "any"
    OUTPUT_FILE = '/tmp/engine_test.out'
    NAMESPACES = ['user']
    VERBOSE = False

def run(args):
    print(args)
    integration = Integration(args)
    integration.run()

def configure(subparsers):
    parser_run = subparsers.add_parser("run", help='Run an integration test')
    parser_run.add_argument('-i', '--agent-id', help=f'Agent ID for event filling',
                        type=str, default=Defaults.AGENT_ID.value, dest='agent_id')

    parser_run.add_argument('-n', '--agent-name', help=f'Agent name for events filling',
                        type=str, default=Defaults.AGENT_NAME.value, dest='agent_name')

    parser_run.add_argument('-a', '--agent-ip', help=f'Agent ip address for events filling',
                        type=str, default=Defaults.AGENT_IP.value, dest='agent_ip')

    parser_run.add_argument('-O', '--origin', help=f'Origin of the integration',
                        type=str, dest='origin')

    parser_run.add_argument('-o', '--output', help=f'Output file where the events will be stored, if empty events wont be saved',
                        type=str, default=Defaults.OUTPUT_FILE.value, dest='output_file')

    parser_run.add_argument('-N', '--namespaces', nargs='+', help=f'Namespaces to include',
                        default=Defaults.NAMESPACES.value, dest='namespaces')

    parser_run.add_argument('-v', '--verbose', help=f'Print traceback on error messages',
                        type=bool, default=Defaults.VERBOSE.value, dest='verbose')

    parser_run.add_argument('integration-name', type=str, help=f'Integration name')
    parser_run.set_defaults(func=run)