from pathlib import Path
import shared.resource_handler as rs
import shared.executor as exec
from shared.default_settings import Constants as DefaultSettings
from api_communication.client import APIClient
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import kvdb_pb2 as api_kvdb
from api_communication.proto.engine_pb2 import GenericStatus_Response


def add_kvdb_task(executor: exec.Executor, client: APIClient, kvdb_path: Path) -> None:
    def do():
        json_request = dict()
        json_request['name'] = kvdb_path.stem
        json_request['path'] = kvdb_path.as_posix()

        error, _ = client.jsend(
            json_request, api_kvdb.managerPost_Request(), GenericStatus_Response())
        if error:
            return error

        return None

    def undo():
        json_request = dict()
        json_request['name'] = kvdb_path.stem

        error, _ = client.jsend(
            json_request, api_kvdb.managerDelete_Request(), GenericStatus_Response())
        if error:
            return error

        return None

    executor.add(exec.RecoverableTask(do, undo, f'Add KVDB: {kvdb_path.stem}'))


def add_asset_task(executor: exec.Executor, client: APIClient, asset_name: str, asset_content: str, namespace: str) -> None:
    def do():
        json_request = dict()
        json_request['content'] = asset_content
        json_request['namespaceid'] = namespace
        json_request['format'] = 'yaml'
        json_request['type'] = asset_name.split('/')[0]

        error, _ = client.jsend(
            json_request, api_catalog.ResourcePost_Request(), GenericStatus_Response())
        if error:
            return error

        return None

    def undo():
        json_request = dict()
        json_request['name'] = asset_name
        json_request['namespaceid'] = namespace

        error, _ = client.jsend(
            json_request, api_catalog.ResourceDelete_Request(), GenericStatus_Response())
        if error:
            return error

        return None

    executor.add(exec.RecoverableTask(do, undo, f'Add asset [{namespace}]: {asset_name}'))


def add_integration(api_socket, namespace, integration_path, dry_run, resource_handler, debug=True):
    # Configuration
    integration_path = Path(integration_path).resolve()
    if not integration_path.exists() or not integration_path.is_dir():
        print(f'Error: {integration_path} is not a directory')
        return -1

    print(f'Adding integration from: {integration_path}')
    ruleset_path = integration_path.parent.parent.resolve()

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

    # Create API client
    client: APIClient
    try:
        client = APIClient(api_socket)
    except Exception as e:
        print(f'Error: {e}')
        return -1

    # Check if integration exists, if so, then inform error
    if not dry_run:
        json_request = dict()
        json_request['name'] = integration_full_name
        json_request['namespaceid'] = namespace
        json_request['format'] = "yaml"

        error, _ = client.jsend(
            json_request, api_catalog.ResourceGet_Request(), api_catalog.ResourceGet_Response())

        if not error:
            print(f'Error: Integration {integration_full_name} already exists')
            return -1

    # Create tasks to add decoders, rules, outputs, filters and kvdbs
    executor = exec.Executor(debug=debug)

    for asset_type in [type for type in manifest.keys() if type in ['decoders', 'rules', 'outputs', 'filters']]:
        assets_path = ruleset_path / asset_type
        if not assets_path.exists():
            print(f'Error: {assets_path} directory does not exist but it is declared in the integration manifest file')
            return -1

        added_kvdbs_paths = []

        # Load all assets that are in the manifest
        assets = [
            (asset_content['name'],
             asset_str, asset_path.parent)
            for asset_path in assets_path.rglob("*.yml")
            if (asset_content := resource_handler.load_file(asset_path.as_posix()))
            and (asset_str := resource_handler.load_file(asset_path.as_posix(), rs.Format.TEXT))
            and 'name' in asset_content
            and asset_content['name'] in manifest[asset_type]
        ]

        # Iterate over the assets and create tasks
        for asset_name, asset_content, kvdbs_path in assets:
            # Kvdbs tasks
            if kvdbs_path.as_posix() not in added_kvdbs_paths:
                added_kvdbs_paths.append(kvdbs_path.as_posix())
                for kvdb_entry in kvdbs_path.glob('*.json'):
                    add_kvdb_task(executor, client, kvdb_entry)

            # Asset task
            add_asset_task(executor, client, asset_name,
                           asset_content, namespace)

    # Integration task
    add_asset_task(executor, client, integration_full_name,
                   manifest_str, namespace)

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
    add_integration(args['api_sock'], args['namespace'], args.get(
        'integration-path'), args['dry-run'], resource_handler)


def configure(subparsers):
    parser_add = subparsers.add_parser(
        'add', help='Add integration components to the Engine Catalog. If a step fails it will undo the previous ones')
    parser_add.add_argument('-a', '--api-sock', type=str, default=DefaultSettings.SOCKET_PATH, dest='api_sock',
                            help=f'[default="{DefaultSettings.SOCKET_PATH}"] Engine instance API socket path')

    parser_add.add_argument('integration-path', type=str,
                            help=f'Integration directory path')

    parser_add.add_argument('--dry-run', dest='dry-run', action='store_true',
                            help=f'When set it will print all the steps to apply but wont affect the store')

    parser_add.add_argument('-n', '--namespace', type=str, dest='namespace', default=DefaultSettings.DEFAULT_NS,
                            help=f'[default={DefaultSettings.DEFAULT_NS}]    Namespace to add the integration to')

    parser_add.set_defaults(func=run)
