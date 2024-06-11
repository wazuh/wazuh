import json

from engine_test.crud_integration import CrudIntegration
from engine_test.command import Command

class GetCommand(Command):
    def __init__(self):
        pass

    def run(self, args):
        super().run(args)
        integration = CrudIntegration()
        try:
            result = integration.get_integration(args['integration-name'])
            if result == None:
                print ("Integration not found!")
            else:
                print(json.dumps(result, indent=4, sort_keys=True, separators=(',', ': ')) + "\n")
        except Exception as ex:
            print(ex)

    def configure(self, subparsers):
        parser_list = subparsers.add_parser("get", help='Get integration')
        parser_list.add_argument('integration-name', type=str, help=f'Integration name')
        parser_list.set_defaults(func=self.run)
