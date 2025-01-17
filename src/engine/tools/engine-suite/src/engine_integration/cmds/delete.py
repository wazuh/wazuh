import yaml
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


def run(args, _: rs.ResourceHandler):
    api_socket = args['api_sock']
    namespace = args['namespace']
    dry_run = args['dry-run']
    integration_name = args['integration-name']

    print(f'Removing integration: {integration_name}')
    print('Importantly, KVDBs will not be removed')
    client: APIClient
    try:
        client = APIClient(api_socket)
    except Exception as e:
        print(f'Error: {e}')
        return -1

    executor = exec.Executor()

    # Get integration from store
    json_request = dict()
    json_request['namespaceid'] = namespace
    json_request['name'] = integration_name
    json_request['format'] = 'yaml'
    error, response = client.jsend(
        json_request, api_catalog.ResourceGet_Request(), api_catalog.ResourceGet_Response())
    if error:
        print(f'Error: {error}')
        return -1

    integration = yaml.safe_load(response['content'])

    # Create tasks to remove all assets from the integration
    for asset_name in [
        asset_name
        for key, asset_list in integration.items()
        if key != "name"
        for asset_name in asset_list
    ]:
        delete_asset_task(executor, client, asset_name, namespace)

    # Remove the integration
    delete_asset_task(executor, client, integration_name, namespace)

    print(f'Deleting {integration_name} from the catalog')
    print('\nTasks:')
    executor.list_tasks()
    print('\nExecuting tasks...')
    executor.execute(dry_run)
    print('\nDone')
    if dry_run:
        print(
            f'If you want to apply the changes, run again without the --dry-run flag')


def configure(subparsers):
    parser_rm = subparsers.add_parser(
        'delete', help='Delete integration assets from the Engine Catalog. If a step fails it continue with the next')
    parser_rm.add_argument('-a', '--api-sock', type=str, default=DefaultSettings.SOCKET_PATH, dest='api_sock',
                           help=f'[default="{DefaultSettings.SOCKET_PATH}"] Engine instance API socket path')

    parser_rm.add_argument('integration-name', type=str,
                           help=f'Integration name to be deleted')

    parser_rm.add_argument('--dry-run', dest='dry-run', action='store_true',
                           help=f'default False, When True will print all the steps to apply without affecting the store')

    parser_rm.add_argument('-n', '--namespace', type=str, dest='namespace', default=DefaultSettings.DEFAULT_NS,
                           help=f'[default="{DefaultSettings.DEFAULT_NS}"] Namespace of the integration')

    parser_rm.set_defaults(func=run)
