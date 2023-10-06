from engine_test.crud_integration import CrudIntegration
from engine_test.command import Command

class AddCommand(Command):
    def __init__(self):
        pass

    def run(self, args):
        super().run(args)
        integration = CrudIntegration()
        integration.save_integration(args['integration-name'], args['format'], args['origin'])

    def configure(self, subparsers):
        parser_add = subparsers.add_parser("add", help='Add integration')
        parser_add.add_argument('integration-name', type=str, help=f'Integration test name')

        parser_add.add_argument('-f', '--format', help='Format of integration. Example: syslog',
                                dest='format')
        parser_add.add_argument('-o', '--origin', help='Origin of integration. Example: /tmp/events.log',
                                dest='origin')

        parser_add.set_defaults(func=self.run)
