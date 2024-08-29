import shared.resource_handler as rs
import shared.executor as exec
from pathlib import Path
from .generate_manifest import run as gen_manifest

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

    print(f'Adding integration from: {working_path}')

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

    # Check if integration exists, if so, then inform error
    if not args['dry-run']:
        try:
            resource_handler.get_store_integration(
                api_socket, integration_name)
            print(
                f'Error {integration_full_name} already exists in the catalog')
            return -1
        except:
            pass

    executor = exec.Executor()

    # Create tasks to add kvdbs
    path = Path(working_path) / 'kvdbs'
    if path.exists():
        for entry in path.rglob('*.json'):
            recoverable_task = resource_handler.get_create_kvdb_task(
                api_socket, entry.stem, str(entry))
            executor.add(recoverable_task)

    # Create tasks to add decoders, rules, outputs and filters
    asset_type = ['decoders', 'rules', 'outputs', 'filters']
    for type_name in asset_type:
        if type_name in manifest:
            path = Path(working_path) / type_name
            if path.exists():
                for entry in path.rglob('*.yml'):
                    if entry.is_file():
                        try:
                            name, original = resource_handler.load_original_asset(
                                entry)
                        except Exception as e:
                            print(f'Error: {e}')
                            return -1

                        # Create task to add asset
                        if name in manifest[type_name]:
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
    executor.execute(args['dry-run'])
    print('\nDone')
    if args['dry-run']:
        print(
            f'If you want to apply the changes, run again without the --dry-run flag')


def configure(subparsers):
    parser_add = subparsers.add_parser(
        'add', help='Add integration components to the Engine Catalog. If a step fails it will undo the previous ones')
    parser_add.add_argument('-a', '--api-sock', type=str, default=DEFAULT_API_SOCK, dest='api_sock',
                            help=f'[default="{DEFAULT_API_SOCK}"] Engine instance API socket path')

    parser_add.add_argument('integration-path', type=str,
                            help=f'[default=current directory] Integration directory path')

    parser_add.add_argument('--dry-run', dest='dry-run', action='store_true',
                            help=f'When set it will print all the steps to apply but wont affect the store')
    
    parser_add.add_argument('-n', '--namespace', type=str, dest='namespace', default=DEFAULT_NAMESPACE,
                            help=f'[default={DEFAULT_NAMESPACE}]    Namespace to add the integration to')

    parser_add.set_defaults(func=run)
