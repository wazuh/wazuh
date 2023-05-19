import shared.resource_handler as rs
from pathlib import Path
from .generate_manifest import run as gen_manifest
import json
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

    # Check if integration exist
    available_integration_assets_list = []
    integration_name = working_path.split('/')[-1]

    available_integration_assets = resource_handler.get_store_integration(
        api_socket, integration_name)
    if available_integration_assets['data']['content']:
        available_integration_assets_json = json.loads(
            available_integration_assets['data']['content'])
    else:
        print(
            f'Error can\'t update if the integration named {integration_name} does not exist')
        exit(1)

    # Get all assets from integration
    asset_type = ['decoders', 'rules', 'outputs', 'filters']
    for type_name in asset_type:
        if type_name in available_integration_assets_json.keys():
            for asset in available_integration_assets_json[type_name]:
                name = str(asset)
                available_integration_assets_list.append(name)

    # Check if any of the KVDB insert can collide and if is the case inform which
    print(f'Checking Kvdbs')
    kvdb_available_list = []
    kvdbs_available_json = resource_handler.get_kvdb_list(api_socket)
    for asset in kvdbs_available_json['data']['dbs']:
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
    for type_name in asset_type:
        # Updates all components from the catalog
        print(f'Updating {type_name}')

        # get all assets of each type decoder from store
        asset_available_list = []
        try:
            asset_on_store = resource_handler.get_catalog_file(
                api_socket, '', type_name[:-1], rs.Format.JSON)
            if asset_on_store['data']['content']:
                asset_on_store_json = json.loads(
                    asset_on_store['data']['content'])
                for asset in asset_on_store_json:
                    name = str(asset)+'/0'
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
                    full_name = f'{type_name[:-1]}/{entry.stem}/0'
                    if full_name in asset_available_list:
                        # Must update
                        old_content = resource_handler.get_catalog_file(
                            api_socket, type_name[:-1], full_name, rs.Format.YML)
                        old_content = old_content['data']['content']
                    # remaining assets in integration list means that should be removed
                    if full_name in available_integration_assets_list:
                        print(f'removed {full_name}')
                        available_integration_assets_list.remove(full_name)
                    asset_group = (full_name, new_content, old_content)
                    # TODO: full_name should be added here
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
                pos = cm.add_command(func_to_update_catalog(api_socket, asset_name.split('/')[0], asset_name, asset_new_content,
                                                            rs.Format.YML),  # update to new
                                     func_to_update_catalog(api_socket, asset_name.split('/')[0], asset_name, old_content_yml,
                                     rs.Format.YML))  # revert to old
                print(f'Asset[{pos}] {asset_name} will be updated.')
            else:
                pos = cm.add_command(func_to_add_catalog(api_socket, type_name[:-1], f'{type_name[:-1]}/{asset_name}/0',
                                                         asset_new_content, rs.Format.YML),
                                     func_to_delete_catalog(api_socket, type_name[:-1], f'{type_name[:-1]}/{asset_name}/0'))
                print(f'Asset[{pos}] {asset_name} will be added.')

    for full_asset_name in available_integration_assets_list:
        print(f'{full_asset_name} will be removed.')
        # get available asset from store
        old_content = resource_handler.get_catalog_file(
            api_socket, full_asset_name.split('/')[0], full_asset_name, rs.Format.YML)
        old_content = old_content['data']['content']
        old_content_yml = yaml.load(asset_old_content, Loader=Loader)

        pos = cm.add_command(func_to_delete_catalog(api_socket, full_asset_name.split('/')[0], full_asset_name),
                             func_to_add_catalog(api_socket, full_asset_name.split('/')[0], full_asset_name,
                                                 old_content_yml, rs.Format.YML))
        print(f'Asset[{pos}] {full_asset_name} will be removed.')

    if args['test-run']:
        print(f'Finish test run.')
    else:
        if not cm.execute():
            print(f'Succesfully updated integration.')
        else:
            print(f'Could not update integration.')


def configure(subparsers):
    parser_update = subparsers.add_parser(
        'update', help=f'Updates all available intgration components, deletes if no longer present, adds when new.')
    parser_update.add_argument('-a', '--api-sock', type=str, default=DEFAULT_API_SOCK, dest='api_sock',
                               help=f'[default="{DEFAULT_API_SOCK}"] Engine instance API socket path')

    parser_update.add_argument('-p', '--integration-path', type=str, dest='integration-path',
                               help=f'[default=current directory] Integration directory path')

    parser_update.add_argument('-t', '--test-run', dest='test-run', action='store_true',
                               help=f'When set it will print all the steps to apply but wont affect the store')

    parser_update.set_defaults(func=run)
