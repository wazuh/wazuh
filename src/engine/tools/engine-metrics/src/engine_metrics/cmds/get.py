import sys
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.metrics_pb2 as emetrics
import api_communication.proto.engine_pb2 as engine

from engine_metrics.defaults import DEFAULT_SOCKET


def run(args):
    client = APIClient(args['api_socket'])

    request = emetrics.Get_Request()
    request.instrumentName = args['name']
    if args.get('space'):
        request.space = args['space']

    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error getting metric: {error}')

    parsed = ParseDict(response, emetrics.Get_Response())
    if parsed.status == engine.ERROR:
        sys.exit(f'Error getting metric: {parsed.error}')

    type_name = parsed.type if parsed.type else 'unknown'
    state = 'enabled' if parsed.enabled else 'disabled'
    print(f'{parsed.name}: {parsed.value}  (type={type_name}, {state})')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser('get', help='Get a single metric value')
    parser.add_argument(
        'name',
        type=str,
        help='Metric name (e.g. router.events.processed)'
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
        help='Space name for per-space metrics (e.g. wazuh)'
    )
    parser.set_defaults(func=run)
