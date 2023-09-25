from engine_test.crud_integration import CrudIntegration

def run(args):
    integration = CrudIntegration()
    integration.save_integration(args['integration-name'], args['format'], args['origin'])

def configure(subparsers):
    parser_add = subparsers.add_parser("add", help='Add an integration test')
    parser_add.add_argument('integration-name', type=str, help=f'Integration test name')

    parser_add.add_argument('-f', '--format', help='Format of integration. Example: syslog',
                            dest='format')
    parser_add.add_argument('-o', '--origin', help='Origin of integration. Example: /tmp/events.log',
                            dest='origin')

    parser_add.set_defaults(func=run)
