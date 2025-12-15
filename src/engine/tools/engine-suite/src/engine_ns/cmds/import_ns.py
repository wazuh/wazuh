import sys
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.crud_pb2 as crud


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)

    json_request = dict()
    json_request['space'] = args['space']

    content = args['jsonContent']
    # Read all content from stdin
    if not content:
        content = sys.stdin.read()

    json_request['jsonContent'] = content
    json_request['force'] = args['force']

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.jsend(
            json_request, crud.namespaceImport_Request(), engine.GenericStatus_Response())

        if error:
            sys.exit(f'Error importing namespace: {error}')

    except Exception as e:
        sys.exit(f'Error importing namespace: {e}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser('import', help='Import a namespace')
    parser.add_argument('space', type=str, help='Name of the namespace')
    parser.add_argument('-c', '--jsonContent', type=str, help='JSON content for the namespace', default='')
    parser.add_argument('--force', action='store_true', help='Force import', default=False)
    parser.set_defaults(func=run)
