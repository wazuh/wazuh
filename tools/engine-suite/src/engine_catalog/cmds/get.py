import sys
from api_communication.client import APIClient
from api_communication.proto.catalog_pb2 import ResourceGet_Request, ResourceGet_Response


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    json_request = dict()
    json_request['namespaceid'] = args['namespace']
    json_request['name'] = args['asset']
    json_request['format'] = args['format']

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.jsend(
            json_request, ResourceGet_Request(), ResourceGet_Response())

        if error:
            sys.exit(f'Error getting asset or collection: {error}')

        print(response['content'])

    except Exception as e:
        sys.exit(f'Error getting asset or collection: {e}')

    return 0


def configure(subparsers):
    parser_get = subparsers.add_parser(
        'get', help='Get asset-type[/asset-id[/item-version]]: Get an asset or list a collection.')

    parser_get.add_argument('asset', type=str,
                            help=f'asset or collection to list: item-type[/item-id]')

    parser_get.set_defaults(func=run)
