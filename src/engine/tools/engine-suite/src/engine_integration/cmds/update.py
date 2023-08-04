import shared.resource_handler as rs
from pathlib import Path
from .generate_manifest import run as gen_manifest
import json
import shared.executor as exec

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

    integration_name = working_path.split('/')[-1]
    
    print(f'Updating integration as defined in path: {working_path}')

    # Load manifest, if it doesn't exists, it will be created with all the assets found
    manifest = dict()
    integration_full_name = ''
    manifest_str = ''
    try:
        print(f'Loading manifest.yml...')
        manifest = resource_handler.load_file(working_path + '/manifest.yml')
        integration_full_name = manifest['name']
        manifest_str = resource_handler.load_file(
            working_path + '/manifest.yml', rs.Format.TEXT)
    except Exception as e:
        print(f'Error: {e}')
        integration_full_name = 'integration/' + integration_name + '/0'
        print(
            f'The manifest will be generated for {integration_full_name} with all the assets found in {working_path}')
        # Generate manifest
        try:
            gen_args = {'output-path': working_path}
            gen_manifest(gen_args, resource_handler)
            manifest = resource_handler.load_file(
                working_path + '/manifest.yml')
            integration_full_name = manifest['name']
            manifest_str = resource_handler.load_file(
                working_path + '/manifest.yml', rs.Format.TEXT)
        except Exception as e:
            print(f'Error: {e}')
            return -1

    # Check if integration exists, if not, then inform error
    current_manifest = dict()
    try:
        resp = resource_handler.get_store_integration(
            api_socket, integration_name)
        current_manifest = json.loads(resp['data']['content'])
    except:
        print("Error: Integration does not exist in the catalog, please use add command")

    executor = exec.Executor()

    # Create tasks to update kvdbs
    current_kvdbs = list()
    try:
        resp = resource_handler.get_kvdb_list(api_socket)
        current_kvdbs = resp['data']['dbs']
    except:
        print("Error: Can't get kvdbs from the engine")
        return -1
    
    path = Path(working_path) / 'kvdbs'
    if path.exists():
        for entry in path.rglob('*.json'):
            # Add kvdb if it doesn't exist
            if entry.stem not in current_kvdbs:
                recoverable_task = resource_handler.get_create_kvdb_task(
                    api_socket, entry.stem, str(entry))
                executor.add(recoverable_task)
            # Update kvdb if it exists 
            # TODO implement update kvdb
            else:
                print(f'Warning: kvdb {entry.stem} already exists, update not implemented yet')

    # Create tasks to update assets
    # Delete assets that are not in the manifest
    for asset_type in ['decoders', 'rules', 'outputs', 'filters']:
        if asset_type in current_manifest:
            for asset in current_manifest[asset_type]:
                if asset_type not in manifest or asset not in manifest[asset_type]:
                    recoverable_task = resource_handler.get_delete_catalog_file_task(
                        api_socket, asset.split('/')[0], asset)
                    executor.add(recoverable_task)
    
    # Create/Update new assets
    for asset_type in ['decoders', 'rules', 'outputs', 'filters']:
        if asset_type in manifest:
            path = Path(working_path) / asset_type
            if path.exists():
                for entry in path.rglob('*.yml'):
                    if entry.is_file():
                        try:
                            name, original = resource_handler.load_original_asset(
                                entry)
                        except Exception as e:
                            print(f'Error: {e}')
                            return -1

                        if name in manifest[asset_type]:
                            # Create task to add asset
                            if asset_type not in current_manifest or name not in current_manifest[asset_type]:
                                task = resource_handler.get_add_catalog_task(
                                    api_socket, name.split('/')[0], name, original)
                                executor.add(task)
                            # Create task to update asset
                            else:
                                task = resource_handler.get_update_catalog_task(
                                    api_socket, name.split('/')[0], name, original)
                                if task:
                                    executor.add(task)
                                else:
                                    print(f'{name} is already up to date')
    
    # Create task to update manifest
    task = resource_handler.get_update_catalog_task(api_socket, integration_full_name.split('/')[0], integration_full_name, manifest_str)
    executor.add(task)

    # Inform the user and execute the tasks
    print(f'Updating {integration_full_name} to the catalog')
    print('\nTasks:')
    executor.list_tasks()
    print('\nExecuting tasks...')
    executor.execute(args['dry-run'])
    print('\nDone')
    if args['dry-run']:
        print(
            f'If you want to apply the changes, run again without the --dry-run flag')

    return 0



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

    # get kvdbs from directory and if possible mark for addition
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

        # get asset from directory and clasiffy if present in store
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
                        available_integration_assets_list.remove(full_name)
                    asset_group = (full_name, new_content, old_content)
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
        # get available asset from store
        old_content = resource_handler.get_catalog_file(
            api_socket, full_asset_name.split('/')[0], full_asset_name, rs.Format.YML)
        old_content = old_content['data']['content']
        old_content_yml = yaml.load(asset_old_content, Loader=Loader)

        pos = cm.add_command(func_to_delete_catalog(api_socket, full_asset_name.split('/')[0], full_asset_name),
                             func_to_add_catalog(api_socket, full_asset_name.split('/')[0], full_asset_name,
                                                 old_content_yml, rs.Format.YML))
        print(f'Asset[{pos}] {full_asset_name} will be removed.')

    if args['dry-run']:
        print(f'Finished test run.')
    else:
        if not cm.execute():
            print(f'Succesfully updated assets. Updating integration.')
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
            print(f'Updating integration [{name}] manifest...')
            try:
                manifest = resource_handler.load_file(manifest_file)
                resource_handler.update_catalog_file(
                    api_socket, 'integration', f'integration/{name}/0', manifest, rs.Format.YML)
            except:
                print('Couldnt update integration to the store, try manually with catalog update')
        else:
            print(f'Could not update integration.')


def configure(subparsers):
    parser_update = subparsers.add_parser(
        'update', help=f'Updates all available intgration components, deletes if no longer present, adds when new.')
    parser_update.add_argument('-a', '--api-sock', type=str, default=DEFAULT_API_SOCK, dest='api_sock',
                               help=f'[default="{DEFAULT_API_SOCK}"] Engine instance API socket path')

    parser_update.add_argument('-p', '--integration-path', type=str, dest='integration-path',
                               help=f'[default=current directory] Integration directory path')

    parser_update.add_argument('--dry-run', dest='dry-run', action='store_true',
                               help=f'When set it will print all the steps to apply but wont affect the store')

    parser_update.set_defaults(func=run)
