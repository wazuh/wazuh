from engine_test.crud_integration import CrudIntegration
from engine_test.command import Command

class AddCommand(Command):
    def __init__(self):
        pass

    def run(self, args):
        super().run(args)
        integration = CrudIntegration()
        if ('integration_path' in args):
            integration.import_integration(args['integration_path'])
        else:
            integration.save_integration(args['integration-name'], args['format'], args['origin'])

    def configure(self, subparsers):
        parser_add = subparsers.add_parser("add", help='Add integration')


        group = parser_add.add_mutually_exclusive_group()


        group.add_argument('-n', '--integration-name', type=str, help=f'Integration test name', dest="integration_name")

        group.add_argument('-p', '--integration-path', type=str, help=f'Integration path to import', dest="integration_path")

        parser_add.add_argument('-f', '--format', help='Format of integration. Example: syslog',
                                dest='format')

        parser_add.add_argument('-o', '--origin', help='Origin of integration. Example: /tmp/events.log',
                                dest='origin')

        parser_add.set_defaults(func=self.run)
