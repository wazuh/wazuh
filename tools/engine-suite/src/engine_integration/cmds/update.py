import shared.resource_handler as rs
from pathlib import Path
from .generate_manifest import run as gen_manifest
import sys
import yaml
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

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
                print(f'Executing N°{idx}')
                pair[0]()
            except Exception as err_inst:
                self.last_command = idx
                print(
                    f'Undoing from N°{self.last_command}, due to error: "{err_inst}"')
                self.undo()
                return 1
        return 0

    def undo(self):
        undo_list = self.commands_list[:(
            self.last_command+1)]
        undo_list.reverse()
        for pair in undo_list:
            try:
                pair[1]()
            except Exception as err_inst:
                print(f'Will continue undoing, despite error: "{inst}"')
                continue


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

    print(f'Updating integration as defined in path: {working_path}')

    cm = CommandsManager()

    # Catalog Functions to functions for undo / redo
    def func_to_update_catalog(api_socket: str, type: str, name: str, content: dict, format: rs.Format):
        def update_catalog():
            resource_handler.update_catalog_file(
                api_socket, type, name, content, format)
        return update_catalog

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

    # Check if any of the KVDB can collide and if is the case inform which
    print(f'Checking Kvdbs')
    kvdb_available_list = []
    asset_available_json = resource_handler.get_kvdb_list(api_socket)
    for asset in asset_available_json['data']['dbs']:
        name = asset.split('/')[-1]
        kvdb_available_list.append(name)

    # get decoder from directory and clasiffy if present in store
    add_kvdbs = []
    path = Path(working_path) / 'kvdbs'
    if path.exists():
        for entry in path.rglob('*.json'):
            if entry.is_file() and entry.stem in kvdb_available_list:
                print(f'Manually check for no missing data in "{entry.stem}"')
            else:
                pos = cm.add_command(func_to_func_create_kvdb(api_socket, entry.stem, str(entry)),
                                     func_to_func_delete_kvdb(api_socket, entry.stem, str(entry)))
                print(f' KVDB "{entry.stem}"[{pos}] will be added.')

    # Iterate over all the possible assets
    asset_type = ['decoders', 'rules', 'outputs', 'filters']

    for type_name in asset_type:
        # Recursively updates all components from the catalog
        print(f'Updating {type_name}')

        # get decoder from store
        asset_available_list = []
        try:
            asset_available_json = resource_handler.get_catalog_file(
                api_socket, '', type_name[:-1], rs.Format.JSON)
            for asset in asset_available_json['data']['content'].split('\n'):
                name = asset.split('/')[-1]
                asset_available_list.append(name)
        except:
            pass

        # get decoder from directory and clasiffy if present in store
        assets_update_list = []
        path = Path(working_path) / type_name
        if path.exists():
            for entry in path.rglob('*'):
                if entry.is_file():
                    old_content = ''
                    new_content = resource_handler.load_file(
                        entry, rs.Format.YML)
                    if entry.stem in asset_available_list:
                        # Must update
                        old_content = resource_handler.get_catalog_file(
                            api_socket, type_name[:-1], f'{type_name[:-1]}/{entry.stem}/0', rs.Format.JSON)
                        old_content = old_content['data']['content']
                    asset_group = (entry.stem, new_content, old_content)
                    assets_update_list.append(asset_group)

        # if item can be updated use old asset as fallback
        # if not add it and undo on error with delete
        for item in assets_update_list:
            asset_name = item[0]
            asset_new_content = item[1]
            asset_old_content = item[2]
            updateable = len(asset_old_content)
            if updateable:
                old_content_yml = yaml.load(asset_old_content, Loader=Loader)
                pos = cm.add_command(func_to_update_catalog(api_socket, f'{type_name[:-1]}/{asset_name}/0',
                                                            f'{type_name[:-1]}/{asset_name}/0', asset_new_content, rs.Format.YML),  # update to new
                                     func_to_update_catalog(api_socket, f'{type_name[:-1]}/{asset_name}/0',
                                                            f'{type_name[:-1]}/{asset_name}/0', old_content_yml, rs.Format.YML))  # revert to old
                print(f'Asset[{pos}] {asset_name} is updatable.')
            else:
                pos = cm.add_command(func_to_add_catalog(api_socket, type_name[:-1], f'{type_name[:-1]}/{asset_name}/0',
                                                         asset_new_content, rs.Format.YML),
                                     func_to_delete_catalog(api_socket, type_name[:-1], f'{type_name[:-1]}/{asset_name}/0'))
                print(f'Asset[{pos}] {asset_name} will be added.')

    print(f'Result {cm.execute()}')

    # TODO: integration update (?)


def configure(subparsers):
    parser_update = subparsers.add_parser(
        'update', help='Updates integration components to the Engine Catalog. If a step fails it will restore the asset to the previous state')
    parser_update.add_argument('-a', '--api-sock', type=str, default=DEFAULT_API_SOCK, dest='api_sock',
                               help=f'[default="{DEFAULT_API_SOCK}"] Engine instance API socket path')

    parser_update.add_argument('-p', '--integration-path', type=str, dest='integration-path',
                               help=f'[default=current directory] Integration directory path')

    parser_update.set_defaults(func=run)
