import shared.resource_handler as rs
from pathlib import Path
import json
import shared.executor as exec
from shared.default_settings import Constants as DefaultSettings

def run(args, resource_handler: rs.ResourceHandler):
    api_socket = args['api_sock']
    namespace = args['namespace']

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
    ruleset_path = Path(working_path).parent.parent.resolve()
    integration_path = Path(working_path).resolve()

    # Load manifest
    manifest = dict()
    integration_full_name = ''
    manifest_str = ''
    try:
        print(f'Loading manifest.yml...')
        manifest_path = integration_path / 'manifest.yml'
        manifest = resource_handler.load_file(manifest_path.as_posix())
        integration_full_name = manifest['name']
        manifest_str = resource_handler.load_file(
            manifest_path.as_posix(), rs.Format.TEXT)
    except Exception as e:
        print(f'Error: {e}')
        return -1

    # Check if integration exists, if not, then inform error
    current_manifest = dict()
    try:
        resp = resource_handler.get_store_integration(
            api_socket, integration_name, namespace)
        current_manifest = json.loads(resp['data']['content'])
    except:
        print("Error: Integration does not exist in the catalog, please use add command")

    executor = exec.Executor()

    # Kvdbs are not updated

    # Create tasks to update assets
    # Delete assets that are not in the manifest
    for asset_type in ['decoders', 'rules', 'outputs', 'filters']:
        if asset_type in current_manifest:
            for asset in current_manifest[asset_type]:
                if asset_type not in manifest or asset not in manifest[asset_type]:
                    recoverable_task = resource_handler.get_delete_catalog_file_task(
                        api_socket, asset.split('/')[0], asset, namespace)
                    executor.add(recoverable_task)

    # Create/Update new assets
    types = ['decoders', 'rules', 'outputs', 'filters']
    for type_name in manifest.keys():
        if type_name not in types:
            continue
        path = ruleset_path / type_name
        if not path.exists():
            print(f'Error: {type_name} directory does not exist')
            return -1

        for entry in path.rglob('*.yml'):
            name, original = resource_handler.load_original_asset(
                entry)
            if name in manifest[type_name]:
                # Create task to add asset
                if type_name not in current_manifest or name not in current_manifest[type_name]:
                    task = resource_handler.get_add_catalog_task(
                        api_socket, name.split('/')[0], name, original, namespace)
                    executor.add(task)
                # Create task to update asset
                else:
                    task = resource_handler.get_update_catalog_task(
                        api_socket, name.split('/')[0], name, original, namespace)
                    if task:
                        executor.add(task)
                    else:
                        print(f'{name} is already up to date')

    # Create task to update manifest
    task = resource_handler.get_update_catalog_task(
        api_socket, integration_full_name.split('/')[0], integration_full_name, manifest_str, namespace)
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


def configure(subparsers):
    parser_update = subparsers.add_parser(
        'update', help=f'Updates all available intgration components, deletes if no longer present, adds when new.')
    parser_update.add_argument('-a', '--api-sock', type=str, default=DefaultSettings.SOCKET_PATH, dest='api_sock',
                               help=f'[default="{DefaultSettings.SOCKET_PATH}"] Engine instance API socket path')

    parser_update.add_argument('-p', '--integration-path', type=str, dest='integration-path',
                               help=f'[default=current directory] Integration directory path')

    parser_update.add_argument('--dry-run', dest='dry-run', action='store_true',
                               help=f'When set it will print all the steps to apply but wont affect the store')

    parser_update.add_argument('-n', '--namespace', type=str, dest='namespace', default=DefaultSettings.DEFAULT_NS,
                               help=f'Namespace to add the integration to')

    parser_update.set_defaults(func=run)
