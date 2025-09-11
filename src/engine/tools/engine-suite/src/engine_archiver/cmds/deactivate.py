import sys

from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.archiver_pb2 as archiver


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)
    request = archiver.ArchiverDeactivate_Request()

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error deactivating archiver: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error deactivating archiver: {parsed_response.error}')
    return 0


def configure(subparsers):
    parser_create = subparsers.add_parser(
        'deactivate', help='Deactivate the archiver')

    parser_create.set_defaults(func=run)
