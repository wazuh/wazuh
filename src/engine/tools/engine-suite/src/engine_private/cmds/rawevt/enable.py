import sys
from importlib import import_module

from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine

rawevtindexer = import_module('api_communication.proto.rawevtindexer_pb2')


def run(args):

    api_socket: str = args['api_socket']

    client = APIClient(api_socket)
    request = rawevtindexer.RawEvtIndexerEnable_Request()

    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error enabling raw event indexer: {error}')

    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error enabling raw event indexer: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        'enable', help='Enable the raw event indexer')

    parser.set_defaults(func=run)
