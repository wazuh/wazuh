

def configure(subparsers):
    parser_modules = subparsers.add_parser(
        'integration', help='Add schema integration fields')
    parser_modules.add_argument('integrations_path', metavar='PATH', type=str, nargs='+',
                                help='Path to the integration directory')


def get_args(args):
    return args['integrations_path']
