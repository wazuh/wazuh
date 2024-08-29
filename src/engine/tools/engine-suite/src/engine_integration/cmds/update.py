import shared.resource_handler as rs
from pathlib import Path
from .generate_manifest import run as gen_manifest
import json
import shared.executor as exec

DEFAULT_API_SOCK = '/var/ossec/queue/sockets/engine-api'
DEFAULT_NAMESPACE = 'user'


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
            api_socket, integration_name, namespace)
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
                print(
                    f'Warning: kvdb {entry.stem} already exists, update not implemented yet')

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
    parser_update.add_argument('-a', '--api-sock', type=str, default=DEFAULT_API_SOCK, dest='api_sock',
                               help=f'[default="{DEFAULT_API_SOCK}"] Engine instance API socket path')

    parser_update.add_argument('-p', '--integration-path', type=str, dest='integration-path',
                               help=f'[default=current directory] Integration directory path')

    parser_update.add_argument('--dry-run', dest='dry-run', action='store_true',
                               help=f'When set it will print all the steps to apply but wont affect the store')

    parser_update.add_argument('-n', '--namespace', type=str, dest='namespace', default=DEFAULT_NAMESPACE,
                               help=f'Namespace to add the integration to')

    parser_update.set_defaults(func=run)
