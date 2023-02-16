

def configure(subparsers):
    parser_modules = subparsers.add_parser(
        'modules', help='Add schema module fields')
    parser_modules.add_argument(
        '--modules-dir', type=str, help='Root directory to find the modules', required=True)
    parser_modules.add_argument('module', metavar='NAME', type=str, nargs='+',
                                help='name of the module to add, a folder under the specified root path must exists with the same name, containing a field.yml with the fields definition and optionally a logpar.json with custom logpar mappings')


def get_args(args):
    modules_dir = args['modules_dir'] if 'modules_dir' in args else None
    modules = args['module'] if 'modules' in args else []

    return modules_dir, modules
