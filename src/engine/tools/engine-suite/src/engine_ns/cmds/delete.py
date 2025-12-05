import sys
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.crud_pb2 as crud


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)

    request = crud.namespaceDelete_Request()
    request.space = args['space']

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error deleting the namespace: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error deleting the namespace: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser('delete', help='Delete a nampescape')
    parser.add_argument('space', type=str, help='Name of the namespace')
    parser.set_defaults(func=run)
