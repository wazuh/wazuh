import shared.resource_handler as rs
from pathlib import Path
from .generate_manifest import run as gen_manifest
import sys

DEFAULT_API_SOCK = '/var/ossec/queue/sockets/engine-api'

class CommandsManager:
    commands_list = []
    last_command = 0

    def add_command(self, command, counter_command):
        self.commands_list.append((command, counter_command))
        return len(self.commands_list) - 1

    def execute(self):
        for idx, pair in enumerate(self.commands_list):
            try:
                print(f'Executing {idx}')
                pair[0]()
            except Exception as err_inst:
                if idx == 0:
                    return 1
                self.last_command = idx - 1
                print(f'Undoing from N°{self.last_command}, due to error: "{err_inst}"')
                self.undo()
                return 1
        return 0

    def undo(self):
        undo_list = self.commands_list[:(
            self.last_command+1)]
        undo_list.reverse()
        for pair in undo_list:
            pair[1]()


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
            exit(1)

    # Check if integration exist, if so, then inform error
    integration_name = working_path.split('/')[-1]

    available_integration_assets = []
    try:
        available_integration_assets = resource_handler.get_store_integration(api_socket, integration_name)
        if available_integration_assets['data']['content']:
            print(f'Error can\'t add if the integration [{integration_name}] already exist')
            exit(1)
    except:
        pass


    print(f'Adding integration from: {working_path}')

    cm = CommandsManager()

    # Catalog Functions to functions for undo / redo
    def func_to_add_catalog(api_socket: str, type: str, name: str, content: dict, format: rs.Format):
        def add_catalog():
            resource_handler.add_catalog_file(
                api_socket, type, name, content, format)
        return add_catalog

    def func_to_delete_catalog(api_socket: str, type: str, name: str):
        def delete_catalog():
            resource_handler.delete_catalog_file(api_socket, type, name)
        return delete_catalog

    # KVDB Functions to functions for undo / redo
    def func_to_func_create_kvdb(api_socket: str, name: str, path: str):
        def func_create_kvdb():
            resource_handler.create_kvdb(api_socket, name, path)
        return func_create_kvdb

    def func_to_func_delete_kvdb(api_socket: str, name: str, path: str):
        def func_delete_kvdb():
            resource_handler.delete_kvdb(api_socket, name, path)
        return func_delete_kvdb

    # get kvdbs from directory and if possible mark for addition
    path = Path(working_path) / 'kvdbs'
    if path.exists():
        for entry in path.rglob('*.json'):
                pos = cm.add_command(func_to_func_create_kvdb(api_socket, entry.stem, str(entry)),
                                     func_to_func_delete_kvdb(api_socket, entry.stem, str(entry)))
                print(f'[{pos}]\tKvdbs [{entry.stem}] will be added')

    asset_type = ['decoders', 'rules', 'outputs', 'filters']
    # get decoder from directory and clasiffy if present in store
    for type_name in asset_type:
        path = Path(working_path) / type_name
        if path.exists():
            for entry in path.rglob('*'):
                if entry.is_file():
                    new_content = resource_handler.load_file(
                        entry, rs.Format.YML)
                    full_name = f'{type_name[:-1]}/{entry.stem}/0'
                    pos = cm.add_command(func_to_add_catalog(api_socket, type_name[:-1], full_name,
                                        new_content, rs.Format.YML),
                                        func_to_delete_catalog(api_socket, type_name[:-1], full_name))
                    print(f'{type_name}[{pos}] {full_name} will be added.')

    if args['dry-run']:
        print(f'Finished test run.')
    elif cm.execute() == 0:
        # Creates a manifest.yml if it doesn't exists
        manifest_file = working_path + '/manifest.yml'
        path = Path(manifest_file)
        if not path.is_file():
            args = {'output-path':working_path} #Is there a better way of doing this?
            print(f'"manifest.yml" not found creating one...')
            gen_manifest(args,resource_handler)
        else:
            print(f'Check if available file is up to date.')

        # integration name is taken from the directory name
        name = path.resolve().parent.name
        print(f'Loading integration [{name}] manifest...')
        try:
            manifest = resource_handler.load_file(manifest_file)
            resource_handler.add_catalog_file(
                api_socket, 'integration', f'integration/{name}/0', manifest, rs.Format.YML)
        except:
            #TODO: should be neccesary to undo the whole proccess for this single step?
            print('Couldnt add integration to the store, try manually with catalog update')
            resource_handler.delete_catalog_file(
                api_socket, 'integration', f'integration/{name}/0')
    else:
        print('Error occur on the adding proccess, policy cleaned')


def configure(subparsers):
    parser_add = subparsers.add_parser(
        'add', help='Add integration components to the Engine Catalog. If a step fails it will undo the previous ones')
    parser_add.add_argument('-a', '--api-sock', type=str, default=DEFAULT_API_SOCK, dest='api_sock',
                            help=f'[default="{DEFAULT_API_SOCK}"] Engine instance API socket path')

    parser_add.add_argument('-p', '--integration-path', type=str, dest='integration-path',
                            help=f'[default=current directory] Integration directory path')

    parser_add.add_argument('--dry-run', dest='dry-run', action='store_true',
                               help=f'When set it will print all the steps to apply but wont affect the store')

    parser_add.set_defaults(func=run)
