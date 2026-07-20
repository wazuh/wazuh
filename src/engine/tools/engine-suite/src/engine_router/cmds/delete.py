import sys
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.router_pb2 as erouter
import api_communication.proto.engine_pb2 as engine


def run(args):

    # Get the params
    api_socket: str = args['api_socket']
    route: str = args['route']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = erouter.RouteDelete_Request()
    request.name = route

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error deleting route: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error deleting route: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser('delete', help='Delete a route')
    parser.add_argument('route', type=str, help='Route to delete')
    parser.set_defaults(func=run)
