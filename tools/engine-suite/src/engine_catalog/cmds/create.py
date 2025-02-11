import sys
from api_communication.client import APIClient
from api_communication.proto.catalog_pb2 import ResourcePost_Request
from api_communication.proto.engine_pb2 import GenericStatus_Response


def run(args):
    # Get the params
    api_socket: str = args['api_socket']

    json_request = dict()
    json_request['namespaceid'] = args['namespace']
    json_request['type'] = args['asset-type']
    json_request['format'] = args['format']

    content = args['content']
    # Read all content from stdin
    if not content:
        content = sys.stdin.read()

    json_request['content'] = content

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.jsend(
            json_request, ResourcePost_Request(), GenericStatus_Response())

        if error:
            sys.exit(f'Error creating asset: {error}')

    except Exception as e:
        sys.exit(f'Error creating asset: {e}')

    return 0


def configure(subparsers):
    parser_create = subparsers.add_parser(
        'create', help='Create an asset.')

    parser_create.add_argument('asset-type', type=str,
                               help=f'Type of asset to create.')

    parser_create.add_argument('-c', '--content', type=str, default='',
                               help='Content of the item, can be passed as argument or '
                               'redirected from a file using the "|" operator or the "<" '
                               'operator.')

    parser_create.set_defaults(func=run)
