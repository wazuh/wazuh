from engine_test.crud_integration import CrudIntegration

def run(args):
    integration = CrudIntegration()
    integrations = integration.get_integrations()
    for item in integrations:
        print(item)

def configure(subparsers):
    parser_list = subparsers.add_parser("list", help='List of integrations test.')
    parser_list.set_defaults(func=run)
