import shared.resource_handler as rs
from pathlib import Path
from .generate_manifest import run as gen_manifest
import sys

DEFAULT_API_SOCK = '/var/ossec/queue/sockets/engine-api'


def run(args, resource_handler: rs.ResourceHandler):
    api_socket = args['api_sock']

    working_path = resource_handler.cwd()
    if args['integration-path']:
        working_path = args['integration-path']
        path = Path(working_path)
        if path.is_dir():
            working_path = str(path.resolve())
        else:
            print(f'Error: Directory does not exist ')
            return -1

    print(f'Removing integration as defined in path: {working_path}')

    # Delete kvdbs
    print(f'Deleting Kvdbs')
    try:
        resource_handler.recursive_delete_kvdbs(api_socket, working_path, True)
    except Exception:
        print('Could not delete kvdb moving to the next step')

    # Recursively delete all components from the catalog
    print(f'Deleting Decoders')
    try:
        resource_handler.recursive_delete_catalog(
        api_socket, working_path, 'decoders', True)
    except Exception:
        print('Could not delete Decoders moving to the next step')

    print(f'Deleting Rules')
    try:
        resource_handler.recursive_delete_catalog(
        api_socket, working_path, 'rules', True)
    except Exception:
        print('Could not delete Rules moving to the next step')

    print(f'Deleting Outputs')
    try:
        resource_handler.recursive_delete_catalog(
        api_socket, working_path, 'outputs', True)
    except Exception:
        print('Could not delete Outputs Outputs moving to the next step')

    print(f'Deleting Filters')
    try:
        resource_handler.recursive_delete_catalog(
        api_socket, working_path, 'filters', True)
    except Exception:
        print('Could not delete Filters moving to the next step')

    # integration name is taken from the directory name
    path = Path(working_path)
    name = path.resolve().name
    print(f'Deleting integration [{name}]')
    try:
        resource_handler.delete_catalog_file(
            api_socket, 'integration', f'integration/{name}/0')
    except:
        print('Could not remove integration from the store')


def configure(subparsers):
    parser_rm = subparsers.add_parser(
        'rm', help='Remove integration components from the Engine Catalog. If a step fails it continue with the next')
    parser_rm.add_argument('-a', '--api-sock', type=str, default=DEFAULT_API_SOCK, dest='api_sock',
                            help=f'[default="{DEFAULT_API_SOCK}"] Engine instance API socket path')

    parser_rm.add_argument('-p', '--integration-path', type=str, dest='integration-path',
                            help=f'[default=current directory] Integration directory path')

    parser_rm.set_defaults(func=run)
