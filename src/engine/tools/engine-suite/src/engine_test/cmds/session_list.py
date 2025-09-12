import sys
import argparse
from google.protobuf.json_format import ParseDict
from shared.dumpers import dict_to_str_json, dict_to_str_yml

from api_communication.client import APIClient
import api_communication.proto.tester_pb2 as etester
import api_communication.proto.engine_pb2 as engine


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = etester.TableGet_Request()

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error getting session list: {error}')

    # Parse the response
    parsed_response = ParseDict(response, etester.TableGet_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error getting session list: {parsed_response.error}')

    # Print the response
    if args['json']:
        print(dict_to_str_json(response['sessions']))
    else:
        print(dict_to_str_yml(response['sessions']))
    return 0


def configure(subparsers):
    parser = subparsers.add_parser('list', help='List all sessions')
    parser.add_argument('-j', '--json', action='store_true',
                    help=f'Output in JSON format (default is YAML)', default=False)
    parser.set_defaults(func=run)
