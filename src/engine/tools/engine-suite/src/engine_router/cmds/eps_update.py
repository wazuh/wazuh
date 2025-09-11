import sys
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.router_pb2 as erouter
import api_communication.proto.engine_pb2 as engine


def run(args):

    # Get the params
    if args['refresh-interval'] < 0:
        sys.exit('The refresh interval must be greater than 0.')

    if args['events-per-second'] < 0:
        sys.exit('The events per second must be greater than 0.')

    api_socket: str = args['api_socket']
    eps: int = args['events-per-second']
    refresh_interval: int = args['refresh-interval']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = erouter.EpsUpdate_Request()
    request.eps = eps
    request.refresh_interval = refresh_interval

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error updating EPS: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error updating EPS: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser('eps-update', help='Change EPS settings.')
    parser.add_argument('refresh-interval', type=int,
                        help='Interval windows size in seconds.')
    parser.add_argument('events-per-second', type=int,
                        help='Number of events per second allowed to be processed.')
    parser.set_defaults(func=run)
