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

    # 1rst approach: Delete and then add kvdbs from file
    # 2nd: get kvdbs, store each key, the ones from new json not present, then insert with value
    print(f'Updating Kvdbs')

    # Recursively updates all components from the catalog
    # get decoder x, save it as tmp json, try to update it, if not succesfull restore tmp
    print(f'Deleting Decoders')
    resource_handler.recursive_delete_catalog(
        api_socket, working_path, 'decoders', True)

    print(f'Deleting Rules')
    resource_handler.recursive_delete_catalog(api_socket, working_path, 'rules', True)

    print(f'Deleting Outputs')
    resource_handler.recursive_delete_catalog(api_socket, working_path, 'outputs', True)

    print(f'Deleting Filters')
    resource_handler.recursive_delete_catalog(api_socket, working_path, 'filters', True)

    # integration update (?)

def configure(subparsers):
    parser_update = subparsers.add_parser(
        'update', help='Updates integration components to the Engine Catalog. If a step fails it will restore the asset to the previous state')
    parser_update.add_argument('-a', '--api-sock', type=str, default=DEFAULT_API_SOCK, dest='api_sock',
                            help=f'[default="{DEFAULT_API_SOCK}"] Engine instance API socket path')

    parser_update.add_argument('-p', '--integration-path', type=str, dest='integration-path',
                            help=f'[default=current directory] Integration directory path')

    parser_update.set_defaults(func=run)
