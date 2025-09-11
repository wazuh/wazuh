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
    namespace: list[str] = args['namespace']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = epolicy.StoreGet_Request()
    request.policy = policy
    request.namespaces.extend(namespace)

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error getting policy: {error}')

    # Parse the response
    parsed_response = ParseDict(response, epolicy.StoreGet_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error getting policy: {parsed_response.error}')

    print(parsed_response.data)

    return 0


def configure(subparsers):
    parser_create = subparsers.add_parser(
        'get', help='Get a policy')

    parser_create.add_argument(
        '-p', '--policy', type=str, help='Policy name to get', default=Constants.DEFAULT_POLICY)
    parser_create.add_argument('-n', '--namespace', type=str,
                               help='Namespace of asset to get', action='append', default=[Constants.DEFAULT_NS])

    parser_create.set_defaults(func=run)
