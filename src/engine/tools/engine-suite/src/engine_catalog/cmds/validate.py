import sys
from api_communication.client import APIClient
from api_communication.proto.catalog_pb2 import ResourceValidate_Request
from api_communication.proto.engine_pb2 import GenericStatus_Response


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    json_request = dict()
    json_request['namespaceid'] = args['namespace']
    json_request['name'] = args['asset-name']
    json_request['format'] = args['format']
    content = args['content']

    # Read all content from stdin
    if not content:
        content = sys.stdin.read()

    json_request['content'] = content

    # validate the api request
    try:
        client = APIClient(api_socket)
        error, response = client.jsend(
            json_request, ResourceValidate_Request(), GenericStatus_Response())

        if error:
            sys.exit(f'Error validating asset: {error}')
    except Exception as e:
        sys.exit(f'Error validating asset: {e}')

    return 0


def configure(subparsers):
    parser_validate = subparsers.add_parser(
        'validate', help='validate an asset.')

    parser_validate.add_argument('asset-name', type=str,
                                 help=f'Name of asset to validate.')

    parser_validate.add_argument('-c', '--content', type=str, default='',
                                 help='Content of the item, can be passed as argument or '
                                 'redirected from a file using the "|" operator or the "<" '
                                 'operator.')

    parser_validate.set_defaults(func=run)
