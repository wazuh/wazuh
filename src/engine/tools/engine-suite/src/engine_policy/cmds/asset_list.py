import sys
from google.protobuf.json_format import ParseDict
from shared.default_settings import Constants

from api_communication.client import APIClient
import api_communication.proto.policy_pb2 as epolicy
import api_communication.proto.engine_pb2 as engine

from shared.dumpers import dict_to_str_yml


def run(args):

    # Get the params
    api_socket: str = args['api_socket']
    policy: str = args['policy']
    namespace: str = args['namespace']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = epolicy.AssetGet_Request()
    request.policy = policy
    request.namespace = namespace

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error getting assets: {error}')

    # Parse the response
    parsed_response = ParseDict(response, epolicy.AssetGet_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error getting assets: {parsed_response.error}')

    # Dictionary to yml
    data: str = dict_to_str_yml(response['data'])
    print(data)

    return 0


def configure(subparsers):
    parser_create = subparsers.add_parser(
        'asset-list', help='List all assets in a policy')

    parser_create.add_argument(
        '-p', '--policy', type=str, help='Policy name to list assets from', default=Constants.DEFAULT_POLICY)
    parser_create.add_argument(
        '-n', '--namespace', type=str, help='Namespace of asset to get', default=Constants.DEFAULT_NS)

    parser_create.set_defaults(func=run)
