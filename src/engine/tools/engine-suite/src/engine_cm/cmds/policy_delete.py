import sys
from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.crud_pb2 as crud


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    json_request = dict()
    json_request['space'] = args['space']

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.jsend(
            json_request, crud.policyDelete_Request(), engine.GenericStatus_Response())

        if error:
            sys.exit(f'Error deleting policy: {error}')

    except Exception as e:
        sys.exit(f'Error deleting policy: {e}')

    return 0


def configure(subparsers):
    parser_upsert = subparsers.add_parser(
        'policy-delete', help='Delete a policy.')

    parser_upsert.set_defaults(func=run)
