from pathlib import Path
import yaml
import shared.resource_handler as rs
import shared.executor as exec
from shared.default_settings import Constants as DefaultSettings
from api_communication.client import APIClient
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import kvdb_pb2 as api_kvdb
from api_communication.proto.engine_pb2 import GenericStatus_Response


def update_kvdb_task(executor: exec.Executor, client: APIClient, kvdb_path: Path) -> None:
    # Backup kvdb
    backup = dict()
    while page := 1 != 0:
        json_request = dict()
        json_request['name'] = kvdb_path.stem
        json_request['page'] = page
        json_request['entries'] = 100

        error, response = client.jsend(
            json_request, api_kvdb.managerDump_Request(), api_kvdb.managerDump_Response())
        if error:
            break

        if not response['entries'] or len(response['entries']) == 0:
            page = 0

        for entry in response['entries']:
            backup[entry['key']] = entry['value']

    def delete():
        json_request = dict()
        json_request['name'] = kvdb_path.stem

        error, _ = client.jsend(
            json_request, api_kvdb.managerDelete_Request(), GenericStatus_Response())

        if error:
            print(f'Error deleting kvdb: {error}')

    def do():
        # Delete kvdb
        delete()

        # Add kvdb
        json_request = dict()
        json_request['name'] = kvdb_path.stem
        json_request['path'] = kvdb_path.as_posix()

        error, _ = client.jsend(
            json_request, api_kvdb.managerPost_Request(), GenericStatus_Response())
        if error:
            return error

        return None

    def undo():
        # Delete kvdb
        delete()

        # Add kvdb backup
        json_request = dict()
        json_request['name'] = kvdb_path.stem

        error, _ = client.jsend(
            json_request, api_kvdb.managerPost_Request(), GenericStatus_Response())
        if error:
            return error

        for key, value in backup.items():
            json_request = dict()
            json_request['name'] = kvdb_path.stem
            json_request['entry'] = {'key': key, 'value': value}

            error, _ = client.jsend(
                json_request, api_kvdb.dbPut_Request(), GenericStatus_Response())
            if error:
                return error

        return None

    executor.add(exec.RecoverableTask(
        do, undo, f'Update KVDB: {kvdb_path.stem}'))


def update_asset_task(executor: exec.Executor, client: APIClient, asset_name: str, asset_content: str, namespace: str) -> None:
    # Backup asset
    backup = ''
    json_request = dict()
    json_request['namespaceid'] = namespace
    json_request['name'] = asset_name
    json_request['format'] = 'json'

    error, response = client.jsend(
        json_request, api_catalog.ResourceGet_Request(), api_catalog.ResourceGet_Response())
    if not error:
        backup = response['content']

    def do():
        json_request = dict()
        json_request['content'] = asset_content
        json_request['namespaceid'] = namespace
        json_request['format'] = 'yaml'
        json_request['name'] = asset_name

        error, _ = client.jsend(
            json_request, api_catalog.ResourcePut_Request(), GenericStatus_Response())
        if error:
            return error

        return None

    def undo():
        json_request = dict()
        json_request['name'] = asset_name
        json_request['namespaceid'] = namespace

        _, _ = client.jsend(
            json_request, api_catalog.ResourceDelete_Request(), GenericStatus_Response())

        if len(backup) != 0:
            json_request = dict()
            json_request['content'] = backup
            json_request['namespaceid'] = namespace
            json_request['format'] = 'json'
            json_request['name'] = asset_name

            error, _ = client.jsend(
                json_request, api_catalog.ResourcePut_Request(), GenericStatus_Response())
            if error:
                return error

        return None

    executor.add(exec.RecoverableTask(
        do, undo, f'Update asset [{namespace}]: {asset_name}'))


def delete_asset_task(executor: exec.Executor, client: APIClient, asset_name: str, namespace: str) -> None:
    backup = ''
    json_request = dict()
    json_request['namespaceid'] = namespace
    json_request['name'] = asset_name
    json_request['format'] = 'json'

    error, response = client.jsend(
        json_request, api_catalog.ResourceGet_Request(), api_catalog.ResourceGet_Response())
    if not error:
        backup = response['content']

    def do():
        json_request = dict()
        json_request['name'] = asset_name
        json_request['namespaceid'] = namespace

        _, _ = client.jsend(
            json_request, api_catalog.ResourceDelete_Request(), GenericStatus_Response())

        return None

    def undo():
        json_request = dict()
        json_request['content'] = backup
        json_request['namespaceid'] = namespace
        json_request['format'] = 'json'
        json_request['type'] = asset_name.split('/')[0]

        error, _ = client.jsend(
            json_request, api_catalog.ResourcePost_Request(), GenericStatus_Response())
        if error:
            return error

        return None

    executor.add(exec.RecoverableTask(
        do, undo, f'Delete asset [{namespace}]: {asset_name}'))


def run(args, resource_handler: rs.ResourceHandler):
    api_socket = args['api_sock']
    namespace = args['namespace']
    integration_path = Path(args['integration-path'])
    if not integration_path.exists() or not integration_path.is_dir():
        print(f'Error: {integration_path.as_posix()} does not exist or is not a directory')
        return -1

    print(f'Updating integration from: {integration_path}')
    print('Ensure that the kvdbs are not being used by any route or test session before updating, otherwise the update will fail as the kvdbs will not be deleted')
    print('Importantly, KVDBs that are not used in the updated integration will not be removed')
    ruleset_path = integration_path.parent.parent.resolve()

    client: APIClient
    try:
        client = APIClient(api_socket)
    except Exception as e:
        print(f'Error: {e}')
        return -1

    # Load updated manifest
    updated_manifest = dict()
    try:
        updated_manifest = resource_handler.load_file(
            integration_path / 'manifest.yml')
    except Exception as e:
        print(f'Error loading new manifest: {e}')
        return -1

    integration_name = updated_manifest['name']

    # Get current manifest
    json_request = dict()
    json_request['namespaceid'] = namespace
    json_request['name'] = integration_name
    json_request['format'] = 'yaml'

    error, response = client.jsend(
        json_request, api_catalog.ResourceGet_Request(), api_catalog.ResourceGet_Response())
    if error:
        print(f'Error loading current manifest: {error}')
        return -1

    current_manifest = yaml.safe_load(response['content'])

    executor = exec.Executor()

    # Begin update process
    for asset_type in [type for type in updated_manifest.keys() if type in ['decoders', 'rules', 'outputs', 'filters']]:
        assets_path = ruleset_path / asset_type
        if not assets_path.exists():
            print(f'Error: {
                  assets_path} directory does not exist but it is declared in the integration manifest file')
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
            and asset_content['name'] in updated_manifest[asset_type]
        ]

        # Iterate over the assets and create tasks
        for asset_name, asset_content, kvdbs_path in assets:
            # Kvdbs tasks
            if kvdbs_path.as_posix() not in added_kvdbs_paths:
                added_kvdbs_paths.append(kvdbs_path.as_posix())
                for kvdb_entry in kvdbs_path.glob('*.json'):
                    update_kvdb_task(executor, client, kvdb_entry)

            # Asset task
            update_asset_task(executor, client, asset_name,
                              asset_content, namespace)

    # Update manifest
    manifest_str = resource_handler.load_file(
        integration_path / 'manifest.yml', rs.Format.TEXT)
    update_asset_task(executor, client, integration_name,
                      manifest_str, namespace)

    # Delete assets that are not in the manifest
    for asset_type in ['decoders', 'rules', 'outputs', 'filters']:
        if asset_type in current_manifest:
            for asset in current_manifest[asset_type]:
                if asset_type not in updated_manifest or asset not in updated_manifest[asset_type]:
                    delete_asset_task(executor, client, asset, namespace)

    # Inform the user and execute the tasks
    print(f'Updating {integration_name} in the catalog')
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

    parser_update.add_argument('integration-path', type=str,
                               help=f'Integration directory path')

    parser_update.add_argument('--dry-run', dest='dry-run', action='store_true',
                               help=f'When set it will print all the steps to apply but wont affect the store')

    parser_update.add_argument('-n', '--namespace', type=str, dest='namespace', default=DefaultSettings.DEFAULT_NS,
                               help=f'Namespace to add the integration to')

    parser_update.set_defaults(func=run)
