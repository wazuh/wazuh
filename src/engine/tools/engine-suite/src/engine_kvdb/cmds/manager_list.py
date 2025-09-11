import sys
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

    request = ekvdb.managerGet_Request()

    # Todo: Add must_be_loaded and filter_by_name when implemented

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error getting the list of key-value databases: {error}')

    # Parse the response
    parsed_response = ParseDict(response, ekvdb.managerGet_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error getting the list of key-value databases: {parsed_response.error}')

    # Print the response
    data: str = dict_to_str_yml(response['dbs'])
    print(data)

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        'list', help='List all key-value databases')

    parser.set_defaults(func=run)
