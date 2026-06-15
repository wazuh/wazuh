import sys
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.metrics_pb2 as emetrics
import api_communication.proto.engine_pb2 as engine

from engine_metrics.defaults import DEFAULT_SOCKET


def run(args):
    client = APIClient(args['api_socket'])

    request = emetrics.List_Request()
    if args.get('space'):
        request.space = args['space']

    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error listing metrics: {error}')

    parsed = ParseDict(response, emetrics.List_Response())
    if parsed.status == engine.ERROR:
        sys.exit(f'Error listing metrics: {parsed.error}')

    for name in parsed.names:
        print(name)

    return 0


def configure(subparsers):
    parser = subparsers.add_parser('list', help='List all registered metric names')
    parser.add_argument(
        '-s', '--api-socket',
        type=str,
        default=DEFAULT_SOCKET,
        help=f'Engine API socket path (default: {DEFAULT_SOCKET})'
    )
    parser.add_argument(
        '--space',
        type=str,
        default=None,
        help='Filter metrics for a specific space'
    )
    parser.set_defaults(func=run)
