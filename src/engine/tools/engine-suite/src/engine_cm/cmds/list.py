import sys
from api_communication.client import APIClient
import api_communication.proto.crud_pb2 as crud


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    json_request = dict()
    json_request['space'] = args['space']
    json_request['type'] = args['type']

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.jsend(
            json_request, crud.resourceList_Request(), crud.resourceList_Response())

        if error:
            sys.exit(f'Error listing resources: {error}')

        print(response['resources'])

    except Exception as e:
        sys.exit(f'Error listing resources: {e}')

    return 0


def configure(subparsers):
    parser_get = subparsers.add_parser(
        'list', help='list type[/name[/version]]: List all resources of a certain type.')

    parser_get.add_argument('type', type=str,
                            help=f'Type of the resource to list.')

    parser_get.set_defaults(func=run)
