import sys
import argparse
from google.protobuf.json_format import ParseDict
from shared.dumpers import dict_to_str_json, dict_to_str_yml

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
    request = etester.SessionGet_Request()
    request.name = name

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error getting session list: {error}')

    # Parse the response
    parsed_response = ParseDict(response, etester.SessionGet_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error getting session list: {parsed_response.error}')

    # Print the response
    if args['json']:
        print(dict_to_str_json(response['session']))
    else:
        print(dict_to_str_yml(response['session']))

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        'get', help='Get information about a session')
    parser.add_argument(
        'name', type=str, help='Name of the session to get information about')
    parser.set_defaults(func=run)
    parser.add_argument('-j', '--json', action='store_true',
                        help=f'Output in JSON format (default is YAML)', default=False)
