import sys
from google.protobuf.json_format import ParseDict
from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.kvdb_pb2 as ekvdb


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)
    request = ekvdb.dbDelete_Request()
    request.name = args['name']
    request.key = args['key']

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error removing the key-value pair: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(
            f'Error removing the key-value pair: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        'remove', help='Remove a pair key-value in the database')
    parser.add_argument(
        'name', type=str, help='Name of the key-value database')
    parser.add_argument('key', type=str, help='Key of the key-value pair')

    parser.set_defaults(func=run)
