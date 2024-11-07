import sys
from google.protobuf.json_format import ParseDict
from shared.dumpers import dict_to_str_yml

from api_communication.client import APIClient
import api_communication.proto.router_pb2 as erouter
import api_communication.proto.engine_pb2 as engine


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = erouter.EpsGet_Request()

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error getting EPS status: {error}')

    # Parse the response
    parsed_response = ParseDict(response, erouter.EpsGet_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error getting EPS status: {parsed_response.error}')

    data = dict_to_str_yml(response)
    print(data)

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        'eps-get', help='Get EPS status on the engine')
    parser.set_defaults(func=run)
