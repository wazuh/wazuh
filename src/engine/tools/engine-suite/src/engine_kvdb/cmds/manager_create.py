import sys
from pathlib import Path
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.kvdb_pb2 as ekvdb
from shared.dumpers import dict_to_str_yml


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)

    request = ekvdb.managerPost_Request()
    request.name = args['name']
    # Resolve Absolute Path
    if args['path'] is not None:
        request.path = Path(args['path']).resolve().as_posix()

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error creating the key-value database: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error creating the key-value database: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        'create', help='Create a new key-value database')
    parser.add_argument('name', type=str, help='Name of the key-value database')
    parser.add_argument(
        'path', type=str, help='Path to the key-value database in the server side (optional)', nargs='?', default=None)

    parser.set_defaults(func=run)
