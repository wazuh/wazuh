import sys
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.router_pb2 as erouter
import api_communication.proto.engine_pb2 as engine


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = erouter.EpsEnable_Request()

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error enabling EPS: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error enabling EPS: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        'eps-enable', help='Enable EPS on the engine')
    parser.set_defaults(func=run)
