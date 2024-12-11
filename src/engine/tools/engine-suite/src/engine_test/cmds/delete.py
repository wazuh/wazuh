from engine_test.crud_integration import CrudIntegration
from engine_test.command import Command

class DeleteCommand(Command):
    def __init__(self):
        pass

    def run(self, args):
        super().run(args)
        integration = CrudIntegration()
        try:
            integration.delete_integration(args['integration-name'])
        except Exception as ex:
            print(ex)

    def configure(self, subparsers):
        parser_list = subparsers.add_parser("delete", help='Delete integration')
        parser_list.add_argument('integration-name', type=str, help=f'Integration name')
        parser_list.set_defaults(func=self.run)
