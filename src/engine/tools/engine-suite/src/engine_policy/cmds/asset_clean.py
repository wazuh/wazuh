import sys
from google.protobuf.json_format import ParseDict
from shared.default_settings import Constants

from api_communication.client import APIClient
import api_communication.proto.policy_pb2 as epolicy
import api_communication.proto.engine_pb2 as engine


def run(args):

    # Get the params
    api_socket: str = args['api_socket']
    policy: str = args['policy']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = epolicy.AssetCleanDeleted_Request()
    request.policy = policy


    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error cleaning deleted assets: {error}')

    # Parse the response
    parsed_response = ParseDict(response, epolicy.AssetCleanDeleted_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error cleaning deleted assets: {parsed_response.error}')

    if parsed_response.data != '':
        print(f'{parsed_response.data}')

    return 0


def configure(subparsers):
    parser_create = subparsers.add_parser(
        'asset-clean-deleted', help='Remove all deleted assets from a policy')

    parser_create.add_argument(
        '-p', '--policy', type=str, help='Policy name to remove asset to', default=Constants.DEFAULT_POLICY)

    parser_create.set_defaults(func=run)
