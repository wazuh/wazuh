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
    namespace: str = args['namespace']
    asset_name: str = args['asset-name']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = epolicy.AssetPost_Request()
    request.policy = policy
    request.asset = asset_name
    request.namespace = namespace

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error adding asset: {error}')

    # Parse the response
    parsed_response = ParseDict(response, epolicy.AssetPost_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error adding asset: {parsed_response.error}')

    if parsed_response.warning != '':
        print(f'Warning: {parsed_response.warning}')

    return 0


def configure(subparsers):
    parser_create = subparsers.add_parser('asset-add', help='Add an asset to a policy')

    parser_create.add_argument('-p', '--policy', type=str, help='Policy name to add asset to', default=Constants.DEFAULT_POLICY)
    parser_create.add_argument('-n', '--namespace', type=str, help='Namespace of asset to add', default=Constants.DEFAULT_NS)
    parser_create.add_argument('asset-name', type=str, help='Name of the asset to add')

    parser_create.set_defaults(func=run)
