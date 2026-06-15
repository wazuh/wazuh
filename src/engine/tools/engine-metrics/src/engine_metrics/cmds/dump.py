import sys
import json
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.metrics_pb2 as emetrics
import api_communication.proto.engine_pb2 as engine

from engine_metrics.defaults import DEFAULT_SOCKET


def run(args):
    client = APIClient(args['api_socket'])

    request = emetrics.Dump_Request()
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error dumping metrics: {error}')

    parsed = ParseDict(response, emetrics.Dump_Response())
    if parsed.status == engine.ERROR:
        sys.exit(f'Error dumping metrics: {parsed.error}')

    print(json.dumps(response, indent=2))
    return 0


def configure(subparsers):
    parser = subparsers.add_parser('dump', help='Dump all metrics with their values')
    parser.add_argument(
        '-s', '--api-socket',
        type=str,
        default=DEFAULT_SOCKET,
        help=f'Engine API socket path (default: {DEFAULT_SOCKET})'
    )
    parser.set_defaults(func=run)
