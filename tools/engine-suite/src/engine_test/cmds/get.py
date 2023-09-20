from engine_test.integration import Integration

def run(args):
    integration = Integration(args)
    result = integration.get_integration(args['integration-name'])
    if result == None:
        print ("Integration not found!")
    else:
        print (result)

def configure(subparsers):
    parser_list = subparsers.add_parser("get", help='List of integrations test.')
    parser_list.add_argument('integration-name', type=str, help=f'Integration name')
    parser_list.set_defaults(func=run)