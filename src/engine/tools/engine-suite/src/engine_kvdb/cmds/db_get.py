import sys
import json
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
    request = ekvdb.dbGet_Request()
    request.name = args['name']
    request.key = args['key']

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error getting the key-value pair: {error}')

    # Parse the response
    parsed_response = ParseDict(response, ekvdb.dbGet_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(
            f'Error getting the key-value pair: {parsed_response.error}')

    # Print the response
    data: str = dict_to_str_yml(response['value'])
    print(data)



    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        'get', help='Get a key-value pair from the database')
    parser.add_argument(
        'name', type=str, help='Name of the key-value database')
    parser.add_argument('key', type=str, help='Key of the key-value pair')

    parser.set_defaults(func=run)
