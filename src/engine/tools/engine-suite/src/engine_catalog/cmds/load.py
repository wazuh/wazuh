import sys
import os
import pathlib
import shared.resource_handler as rs
from shared.resource_handler import Format, StringToFormat


def run(args, resource_handler: rs.ResourceHandler):

    # Get the params
    api_socket: str = args['api_socket']
    namespace: str = args['namespace']
    type: str = args['asset-type']
    inFormat: Format = StringToFormat(args['format'])
    path: pathlib.Path = pathlib.Path(args['path'])
    recursive: bool = args['recursive']
    abort_on_error: bool = args.get('abort_on_error', False)

    # Check if the path exists and is a directory
    if not path.exists():
        sys.exit(f'Error: Path {path} does not exist.')

    if not path.is_dir():
        print(f'Error: Path {path} is not a directory.')

    # List all the files in the path
    files : list[str] = []
    for root, _, filenames in os.walk(path.absolute().as_posix()):
        for filename in filenames:
            if (inFormat == Format.JSON and filename.endswith('.json')) \
               or (inFormat == Format.YML and filename.endswith(('.yaml', '.yml'))):
                files.append(os.path.join(root, filename))
            else:
                print(f'Warning: Ignoring file {filename}.')
                continue
        if not recursive:
            break

    # Load all the files
    for file in files:
        try:
            with open(file, 'r') as f:
                print(f'Loading file {file}')
                content = f.read()
                resource_handler.add_catalog_file(
                    api_socket, type, '', content, namespace, inFormat)
        except Exception as e:
            print(f'Error updating asset: {e}')
            if abort_on_error:
                exit(1)
            continue

    return 0


def configure(subparsers):
    parser_load = subparsers.add_parser('load', help='Load item-type path: Tries to '
                                        'create and add all the items found in the path'
                                        ' to the collection.')

    parser_load.add_argument('asset-type', type=str,
                             help=f'Type of asset to load. The supported asset types '
                             'are: "decoder", "rule", "filter", "output", "schema"')

    parser_load.add_argument(
        'path', type=str, help='Path to the directory containing the asset collection.')

    parser_load.add_argument('-r', '--recursive', action='store_true',
                             help='Recursively load of all the items in the path.')

    parser_load.add_argument('-a', '--abort-on-error', action='store_true',
                             help='Abort the load if an error is found.')

    parser_load.set_defaults(func=run)
