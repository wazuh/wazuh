def run(args):
    print("Add command")

def configure(subparsers):
    parser_add = subparsers.add_parser("add", help='Add an integration test.')
    parser_add.add_argument('integration-name', type=str, help=f'Integration test name.')
    parser_add.add_argument('config', type=str, help=f'Json with configuration of integration.')
    parser_add.set_defaults(func=run)