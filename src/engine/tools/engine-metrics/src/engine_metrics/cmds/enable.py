import sys
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.metrics_pb2 as emetrics
import api_communication.proto.engine_pb2 as engine

from engine_metrics.defaults import DEFAULT_SOCKET


def _run(args, enable: bool):
    client = APIClient(args['api_socket'])

    request = emetrics.Enable_Request()
    request.instrumentName = args['name']
    request.status = enable
    if args.get('space'):
        request.space = args['space']

    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error: {error}')

    parsed = ParseDict(response, emetrics.Enable_Response())
    if parsed.status == engine.ERROR:
        sys.exit(f'Error: {parsed.error}')

    action = 'enabled' if enable else 'disabled'
    print(f'Metric "{args["name"]}" {action}')

    return 0


def run_enable(args):
    return _run(args, enable=True)


def run_disable(args):
    return _run(args, enable=False)


def _add_common_args(parser):
    parser.add_argument(
        'name',
        type=str,
        help='Metric name'
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


def configure_enable(subparsers):
    parser = subparsers.add_parser('enable', help='Enable a metric')
    _add_common_args(parser)
    parser.set_defaults(func=run_enable)


def configure_disable(subparsers):
    parser = subparsers.add_parser('disable', help='Disable a metric')
    _add_common_args(parser)
    parser.set_defaults(func=run_disable)
