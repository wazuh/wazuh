import sys
from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.crud_pb2 as crud


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    json_request = dict()
    json_request['space'] = args['space']
    json_request['uuid'] = args['uuid']

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.jsend(
            json_request, crud.resourceDelete_Request(), engine.GenericStatus_Response())

        if error:
            sys.exit(f'Error deleting resource: {error}')
    except Exception as e:
        sys.exit(f'Error deleting resource: {e}')

    return 0


def configure(subparsers):
    parser_delete = subparsers.add_parser(
        'delete', help='delete type[/name[/version]]: Delete an resource.')

    parser_delete.add_argument('uuid', type=str,
                               help=f'UUID of the resource to delete.')

    parser_delete.set_defaults(func=run)
