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
    parent_name: str = args['parent_name']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = epolicy.DefaultParentDelete_Request()
    request.policy = policy
    request.parent = parent_name
    request.namespace = namespace

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error setting default parent: {error}')

    # Parse the response
    parsed_response = ParseDict(response, epolicy.DefaultParentDelete_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error setting default parent: {parsed_response.error}')

    if parsed_response.warning != '':
        print(f'Warning: {parsed_response.warning}')

    return 0


def configure(subparsers):
    parser_create = subparsers.add_parser('parent-remove', help='Remove the default parent for assets under a specific namespace')

    parser_create.add_argument('-p', '--policy', type=str, help='Name of the policy to remove the default parent', default=Constants.DEFAULT_POLICY)
    parser_create.add_argument('-n', '--namespace', type=str, help='Namespace to remove the default parent', default=Constants.DEFAULT_NS)
    parser_create.add_argument('parent_name', type=str, help='Name of the default parent')

    parser_create.set_defaults(func=run)
