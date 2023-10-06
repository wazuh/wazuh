from engine_test.crud_integration import CrudIntegration
from engine_test.command import Command

class ListCommand(Command):
    def __init__(self):
        pass

    def run(self, args):
        super().run(args)
        integration = CrudIntegration()
        integrations = integration.get_integrations()
        for item in integrations:
            print(item)

    def configure(self, subparsers):
        parser_list = subparsers.add_parser("list", help='List of integrations')
        parser_list.set_defaults(func=self.run)
