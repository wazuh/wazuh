import sys
import json
from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.crud_pb2 as crud


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    json_request = dict()

    content = args['full_policy']
    # Read all content from stdin
    if not content:
        content = sys.stdin.read()

    json_request['full_policy'] = json.loads(content)
    json_request['load_in_tester'] = args['load_in_tester']

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.jsend(
            json_request, crud.policyValidate_Request(), engine.GenericStatus_Response())

        if error:
            sys.exit(f'Error validating policy: {error}')

    except Exception as e:
        sys.exit(f'Error validating policy: {e}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser('policy-validate', help='Validate a policy')
    parser.add_argument('-c', '--full-policy', type=str, help='JSON content for the namespace', default='')
    parser.add_argument('--load-in-tester', action='store_true', help='Force testing load', default=False)
    parser.set_defaults(func=run)
