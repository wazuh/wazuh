import sys
from google.protobuf.json_format import ParseDict
from shared.default_settings import Constants
from shared.dumpers import dict_to_str_yml

from api_communication.client import APIClient
import api_communication.proto.router_pb2 as erouter
import api_communication.proto.engine_pb2 as engine


def run(args):

    # Get the params
    api_socket: str = args['api_socket']
    route: str = args['route']
    valid_update = False

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = erouter.RoutePatchPriority_Request()
    request.name = route

    # Check if the priority must be updated and if it is valid
    if args['priority'] is not None:
        prior: int = args['priority']
        if prior < 0:
            sys.exit(f'Priority must be a positive integer')
        valid_update = True
        request.priority = prior

    # Check if a valid update was provided
    if not valid_update:
        sys.exit(f'No data was provided to update the route')

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error updating route: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error updating route: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        'update', help='Update a route. it only supports the update of the priority')
    parser.add_argument('route', type=str, help='Route to update')
    parser.add_argument('--priority', type=int,
                        help='New priority of the route', default=None)
    parser.set_defaults(func=run)
