from engine_test.integration import Integration

def run(args):
    integration = Integration(args)
    integration.run()

def configure(subparsers):
    parser_run = subparsers.add_parser("run", help='Run an integration test')
    parser_run.add_argument('integration-name', type=str, help=f'Integration name')
    parser_run.set_defaults(func=run)