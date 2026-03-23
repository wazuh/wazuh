import sys
import json
from google.protobuf import json_format
from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.crud_pb2 as crud


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    content = args['full_policy']
    # Read all content from stdin
    if not content:
        content = sys.stdin.read()

    req = crud.policyValidate_Request()
    data = json.loads(content)
    json_format.ParseDict(data, req.full_policy)
    req.load_in_tester = args['load_in_tester']
    req.space = args['space']

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.send(req, engine.GenericStatus_Response())

        if error:
            sys.exit(f'Error validating policy: {error}')

    except Exception as e:
        sys.exit(f'Error validating policy: {e}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser('policy-validate', help='Validate a policy')
    parser.add_argument('-c', '--full-policy', type=str, help='JSON content for the namespace', default='')
    parser.add_argument('-n', '--space', type=str, required=True, help='Target space/session name (e.g. test, standard)')
    parser.add_argument('--load-in-tester', action='store_true', help='Force testing load', default=False)
    parser.set_defaults(func=run)
