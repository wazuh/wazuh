import sys
import argparse
from google.protobuf.json_format import ParseDict
from shared.dumpers import dict_to_str_json

from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.tester_pb2 as etester



def run(args):

    # Get the params
    api_socket: str = args['api_socket']
    name: str = args['name']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = etester.SessionDelete_Request()
    request.name = name

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error deleting session: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error deleting session: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        'delete', help='Delete a session for testing')
    parser.add_argument(
        'name', type=str, help='Name of the session to delete')
    parser.set_defaults(func=run)
