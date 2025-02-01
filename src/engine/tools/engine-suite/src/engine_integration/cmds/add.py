import shared.resource_handler as rs
import shared.executor as exec
from pathlib import Path

from shared.default_settings import Constants as DefaultSettings


def add_integration(api_socket, namespace, integration_path, dry_run, resource_handler):

    working_path = resource_handler.cwd() if not integration_path else integration_path
    path = Path(working_path)
    if path.is_dir():
        working_path = str(path.resolve())
    else:
        print(f'Error: Directory does not exist')
        return -1

    integration_name = working_path.split('/')[-1]

    print(f'Adding integration from: {working_path}')
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

    # Check if integration exists, if so, then inform error
    if not dry_run:
        try:
            resource_handler.get_store_integration(
                api_socket, integration_name)
            print(
                f'Error {integration_full_name} already exists in the catalog')
            return -1
        except:
            pass

    executor = exec.Executor()

    # Create tasks to add decoders, rules, outputs, filters and kvdbs
    types = ['decoders', 'rules', 'outputs', 'filters']
    for type_name in manifest.keys():
        if type_name not in types:
            continue
        path = ruleset_path / type_name
        if not path.exists():
            print(f'Error: {type_name} directory does not exist')
            return -1
        added_kvdbs_paths = []
        for entry in path.rglob('*.yml'):
            name, original = resource_handler.load_original_asset(
                entry)
            if name in manifest[type_name]:
                # Find if kvdbs are present in the same folder and it are not alrready added
                if entry.parent.as_posix() not in added_kvdbs_paths:
                    added_kvdbs_paths.append(entry.parent.as_posix())
                    for kvdb_entry in entry.parent.glob('*.json'):
                        recoverable_task = resource_handler.get_create_kvdb_task(
                            api_socket, kvdb_entry.stem, str(kvdb_entry))
                        executor.add(recoverable_task)
                task = resource_handler.get_add_catalog_task(
                    api_socket, name.split('/')[0], name, original, namespace)
                executor.add(task)

    # Create task to add integration
    integration_task = resource_handler.get_add_catalog_task(
        api_socket, 'integration', integration_full_name, manifest_str, namespace)
    executor.add(integration_task)

    # Inform the user and execute the tasks
    print(f'Adding {integration_full_name} to the catalog')
    print('\nTasks:')
    executor.list_tasks()
    print('\nExecuting tasks...')
    executor.execute(dry_run)
    print('\nDone')
    if dry_run:
        print(
            f'If you want to apply the changes, run again without the --dry-run flag')

def run(args, resource_handler):
    add_integration(args['api_sock'], args['namespace'], args.get('integration-path'), args['dry-run'], resource_handler)


def configure(subparsers):
    parser_add = subparsers.add_parser(
        'add', help='Add integration components to the Engine Catalog. If a step fails it will undo the previous ones')
    parser_add.add_argument('-a', '--api-sock', type=str, default=DefaultSettings.SOCKET_PATH, dest='api_sock',
                            help=f'[default="{DefaultSettings.SOCKET_PATH}"] Engine instance API socket path')

    parser_add.add_argument('integration-path', type=str,
                            help=f'[default=current directory] Integration directory path')

    parser_add.add_argument('--dry-run', dest='dry-run', action='store_true',
                            help=f'When set it will print all the steps to apply but wont affect the store')

    parser_add.add_argument('-n', '--namespace', type=str, dest='namespace', default=DefaultSettings.DEFAULT_NS,
                            help=f'[default={DefaultSettings.DEFAULT_NS}]    Namespace to add the integration to')

    parser_add.set_defaults(func=run)
