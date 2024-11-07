import sys
from google.protobuf.json_format import ParseDict
from shared.dumpers import dict_to_str_yml

from api_communication.client import APIClient
import api_communication.proto.router_pb2 as erouter
import api_communication.proto.engine_pb2 as engine


def run(args):

    # Get the params
    api_socket: str = args['api_socket']
    route: str = args['route']
    policy: str = args['policy']
    filter_asset: str = args['filter']
    priority: int = args['priority']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = erouter.RoutePost_Request()
    request.route.name = route
    request.route.policy = policy
    request.route.filter = filter_asset
    request.route.priority = priority
    if args['description']:
        request.route.description = args['description']

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error getting route: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error getting route: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser('add', help='Add a route')
    parser.add_argument('route', type=str, help='Name of the route')
    parser.add_argument('filter', type=str, help='Name of the filter asset')
    parser.add_argument('priority', type=int,
                        help='Priority of the route (0 is the highest)')
    parser.add_argument('policy', type=str, help='Name of the policy')
    parser.add_argument('-d', '--description', type=str,
                        help='Description of the route (optional)', default=None)
    parser.set_defaults(func=run)
