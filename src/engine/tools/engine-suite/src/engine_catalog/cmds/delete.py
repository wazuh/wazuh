import sys
from api_communication.client import APIClient
from api_communication.proto.catalog_pb2 import ResourceDelete_Request
from api_communication.proto.engine_pb2 import GenericStatus_Response


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    json_request = dict()
    json_request['namespaceid'] = args['namespace']
    json_request['name'] = args['asset']

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.jsend(
            json_request, ResourceDelete_Request(), GenericStatus_Response())

        if error:
            sys.exit(f'Error deleting asset or collection: {error}')
    except Exception as e:
        sys.exit(f'Error deleting asset or collection: {e}')

    return 0


def configure(subparsers):
    parser_delete = subparsers.add_parser(
        'delete', help='delete asset-type[/asset-name[/version]]: Delete an asset or a collection.')

    parser_delete.add_argument('asset', type=str,
                               help=f'asset or collection to delete: asset-type[/asset-name[/version]]')

    parser_delete.set_defaults(func=run)
