import sys
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.geo_pb2 as egeo


def run(args):

    # Get the params
    api_socket: str = args['api_socket']
    path: str = args['path']

    # Create API client
    client = APIClient(api_socket)

    request = egeo.DbDelete_Request()
    request.path = path

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error deleting GeoIP database: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error deleting GeoIP database: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser_create = subparsers.add_parser(
        'delete', help='Remove a GeoIP database')

    parser_create.add_argument(
        'path', type=str, help='Path to the GeoIP database to remove')

    parser_create.set_defaults(func=run)
