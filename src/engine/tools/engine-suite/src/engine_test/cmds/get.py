from engine_test.crud_integration import CrudIntegration

def run(args):
    integration = CrudIntegration()
    result = integration.get_integration(args['integration-name'])
    if result == None:
        print ("Integration not found!")
    else:
        print (result)

def configure(subparsers):
    parser_list = subparsers.add_parser("get", help='Get integration test format.')
    parser_list.add_argument('integration-name', type=str, help=f'Integration name')
    parser_list.set_defaults(func=run)
