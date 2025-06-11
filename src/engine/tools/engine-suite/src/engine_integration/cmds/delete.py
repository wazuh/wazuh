import yaml
from pathlib import Path
import shared.resource_handler as rs
import shared.executor as exec
from shared.default_settings import Constants as DefaultSettings
from api_communication.client import APIClient
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import kvdb_pb2 as api_kvdb
from api_communication.proto.engine_pb2 import GenericStatus_Response

def delete_asset_task(executor: exec.Executor, client: APIClient, asset_name: str, namespace: str) -> None:
    # Backup asset
    json_request = dict()
    json_request['namespaceid'] = namespace
    json_request['name'] = asset_name
    json_request['format'] = 'json'

    error, response = client.jsend(
        json_request, api_catalog.ResourceGet_Request(), api_catalog.ResourceGet_Response())
    if error:
        raise Exception(f'Error getting asset {asset_name} backup: {error}')

    asset_backup = response['content']

    def do():
        json_request = dict()
        json_request['name'] = asset_name
        json_request['namespaceid'] = namespace

        error, _ = client.jsend(
            json_request, api_catalog.ResourceDelete_Request(), GenericStatus_Response())
        if error:
            return error

        return None

    def undo():
        json_request = dict()
        json_request['content'] = asset_backup
        json_request['namespaceid'] = namespace
        json_request['format'] = 'json'
        json_request['type'] = asset_name.split('/')[0]

        error, _ = client.jsend(
            json_request, api_catalog.ResourcePost_Request(), GenericStatus_Response())
        if error:
            return error

        return None

    executor.add(exec.RecoverableTask(do, undo, f'Delete asset [{namespace}]: {asset_name}'))


def run(args, resource_handler):
    api_socket    = args['api_sock']
    namespace     = args['namespace']
    dry_run       = args['dry-run']
    integration_path = Path(args['integration-path']).resolve()

    # --- Load manifest ---
    manifest_file = integration_path / 'manifest.yml'
    manifest = resource_handler.load_file(manifest_file.as_posix())
    integration_name = manifest['name']
    print(f"Removing integration: {integration_name}")

    # --- Init API client ---
    try:
        client = APIClient(api_socket)
    except Exception as e:
        print(f"Error connecting to API socket '{api_socket}': {e}")
        return -1

    executor = exec.Executor()

    # --- Fetch remote integration definition ---
    get_req = {
        'namespaceid': namespace,
        'name':        integration_name,
        'format':      'yaml'
    }
    error, response = client.jsend(
        get_req,
        api_catalog.ResourceGet_Request(),
        api_catalog.ResourceGet_Response()
    )
    if error:
        print(f"Error fetching integration '{integration_name}': {error}")
        return -1

    integration = yaml.safe_load(response['content'])

    # --- Prepare asset list ---
    assets = [
        asset
        for key, lst in integration.items()
        if key != 'name'
        for asset in lst
    ]
    decoders_root = integration_path.parent.parent / 'decoders'

    # --- Schedule deletion tasks for each asset and its KVDBs ---
    for asset in assets:
        delete_asset_task(executor, client, asset, namespace)

        # find matching decoder folder
        for subdir in decoders_root.iterdir():
            if not subdir.is_dir():
                continue

            # check each YAML for a matching "name"
            for yml in subdir.glob('*.yml'):
                decoder = resource_handler.load_file(yml.as_posix())
                if decoder.get('name') != asset:
                    continue

                # delete all KVDB JSONs in that folder
                for json_path in subdir.glob('*.json'):
                    kvdb_name = json_path.stem
                    err, _ = client.jsend(
                        {'name': kvdb_name},
                        api_kvdb.managerDelete_Request(),
                        GenericStatus_Response()
                    )
                    if err:
                        raise Exception(f"Error deleting KVDB '{kvdb_name}': {err}")
                    print(f"Deleted KVDB: {kvdb_name}")
                break  # found & processed this decoder
            else:
                continue
            break  # move to next asset

    delete_asset_task(executor, client, integration_name, namespace)

    print(f"\nDeleting {integration_name} from the catalog")
    print("\nTasks:")
    executor.list_tasks()
    print("\nExecuting tasks...")
    executor.execute(dry_run)
    print("\nDone")
    if dry_run:
        print("If you want to apply the changes, run again without the --dry-run flag")


def configure(subparsers):
    parser_rm = subparsers.add_parser(
        'delete', help='Delete integration assets from the Engine Catalog. If a step fails it continue with the next')
    parser_rm.add_argument('-a', '--api-sock', type=str, default=DefaultSettings.SOCKET_PATH, dest='api_sock',
                           help=f'[default="{DefaultSettings.SOCKET_PATH}"] Engine instance API socket path')

    parser_rm.add_argument('integration-path', type=str,
                           help=f'Integration path to be deleted')

    parser_rm.add_argument('--dry-run', dest='dry-run', action='store_true',
                           help=f'default False, When True will print all the steps to apply without affecting the store')

    parser_rm.add_argument('-n', '--namespace', type=str, dest='namespace', default=DefaultSettings.DEFAULT_NS,
                           help=f'[default="{DefaultSettings.DEFAULT_NS}"] Namespace of the integration')

    parser_rm.set_defaults(func=run)
