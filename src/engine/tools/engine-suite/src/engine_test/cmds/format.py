from engine_test.cmds.run import RunCommand
from engine_test.integration import Integration

class FormatCommand(RunCommand):
    def __init__(self):
        self.isFormat = True

    def run(self, args):
        self.set_config_file(args)
        integration = Integration(args)
        integration.run(interactive = False)

    def create_parser(self, subparsers: any):
        parser = subparsers.add_parser('format', help='Format integration')
        parser.add_argument('-e', '--event', help=f'Event to test.',
                            dest='event')
        return parser
