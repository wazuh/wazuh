import pathlib
from engine_test.command import Command
from engine_test.integration import Integration

DEFAULT_AGENT_ID = "001"
DEFAULT_AGENT_NAME = "wazuh-agent-1"
DEFAULT_AGENT_IP = "any"
DEFAULT_NAMESPACES = ['user']
DEFAULT_VERBOSE = False
DEFAULT_POLICY = "policy/wazuh/0"
DEFAULT_ASSETS = []


class RunCommand(Command):
    def __init__(self):
        pass

    def run(self, args):
        super().run(args)
        integration = Integration(args)
        integration.run()

    def configure(self, subparsers):
        parser_run = self.create_parser(subparsers)
        parser_run.add_argument('-i', '--agent-id', help=f'Agent ID for event filling',
                                type=str, default=DEFAULT_AGENT_ID, dest='agent_id')

        parser_run.add_argument('-n', '--agent-name', help=f'Agent name for events filling',
                                type=str, default=DEFAULT_AGENT_NAME, dest='agent_name')

        parser_run.add_argument('-a', '--agent-ip', help=f'Register agent ip for events filling',
                                type=str, default=DEFAULT_AGENT_IP, dest='agent_ip')

        parser_run.add_argument('-O', '--origin', help=f'Origin of the integration',
                                type=str, dest='origin')

        parser_run.add_argument('-o', '--output', help=f'Output file where the events will be stored, if empty events wont be saved',
                                type=pathlib.Path, dest='output_file')

        parser_run.add_argument('-N', '--namespaces', nargs='+', help=f'List of namespaces to include',
                                default=DEFAULT_NAMESPACES, dest='namespaces')

        group = parser_run.add_mutually_exclusive_group()

        group.add_argument('-p', '--policy', help=f'Policy where to run the test',
                        default=DEFAULT_POLICY, dest='policy')
        group.add_argument('-s', '--session-name', help=f'Session where to run the test',
                        dest='session_name')

        parser_run.add_argument('-d', '--debug', action='store_true', help=f'Log asset history',
                                default=DEFAULT_VERBOSE, dest='verbose')

        parser_run.add_argument('-D', '--full-debug', action='store_true', help=f'Log asset history and full tracing',
                                default=DEFAULT_VERBOSE, dest='full_verbose')

        parser_run.add_argument('-t', '--trace', nargs='+', help=f'List of assets to filter trace',
                                default=DEFAULT_ASSETS, dest='assets')

        parser_run.add_argument('integration-name', type=str, help=f'Integration name')
        parser_run.set_defaults(func=self.run)

    def create_parser(self, subparsers: any):
        return subparsers.add_parser('run', help='Run integration')
