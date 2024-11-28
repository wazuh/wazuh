import sys
from google.protobuf.json_format import ParseDict
from google.protobuf.json_format import MessageToDict

from shared.dumpers import dict_to_str_yml

from api_communication.client import APIClient
import api_communication.proto.policy_pb2 as epolicy
import api_communication.proto.engine_pb2 as engine

def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = epolicy.PoliciesGet_Request()

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error getting policies: {error}')

    # Parse the response
    parsed_response = ParseDict(response, epolicy.PoliciesGet_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error getting policies: {parsed_response.error}')

    # Message to dic
    data : str = dict_to_str_yml(response['data'])
    print(data)

    return 0


def configure(subparsers):
    parser_create = subparsers.add_parser('list', help='List all policies')
    parser_create.set_defaults(func=run)
