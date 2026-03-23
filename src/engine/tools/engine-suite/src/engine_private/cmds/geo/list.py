import sys
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.geo_pb2 as egeo
from shared.dumpers import dict_to_str_yml


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)

    request = egeo.DbList_Request()

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error adding GeoIP database: {error}')

    # Parse the response
    parsed_response = ParseDict(response, egeo.DbList_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error adding GeoIP database: {parsed_response.error}')

    # Print the response
    data: str = dict_to_str_yml(response['entries'])
    print(data)

    return 0


def configure(subparsers):
    parser_create = subparsers.add_parser(
        'list', help='List all GeoIP databases in use by the manager')

    parser_create.set_defaults(func=run)
