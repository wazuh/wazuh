import sys
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.metrics_pb2 as emetrics
import api_communication.proto.engine_pb2 as engine

from engine_metrics.defaults import DEFAULT_SOCKET


def run(args):
    client = APIClient(args['api_socket'])

    request = emetrics.Enable_Request()
    request.instrumentName = args['name']
    request.status = args['status'].lower() in ('true', '1', 'yes')
    if args.get('space'):
        request.space = args['space']

    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error enabling metric: {error}')

    parsed = ParseDict(response, emetrics.Enable_Response())
    if parsed.status == engine.ERROR:
        sys.exit(f'Error enabling metric: {parsed.error}')

    action = 'enabled' if request.status else 'disabled'
    print(f'Metric "{args["name"]}" {action}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser('enable', help='Enable or disable a metric')
    parser.add_argument(
        'name',
        type=str,
        help='Metric name'
    )
    parser.add_argument(
        '--status',
        type=str,
        required=True,
        help='true/false to enable/disable'
    )
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
        help='Space name for per-space metrics'
    )
    parser.set_defaults(func=run)
