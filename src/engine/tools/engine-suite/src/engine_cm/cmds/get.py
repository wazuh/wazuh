import sys
from api_communication.client import APIClient
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
            json_request, crud.resourceGet_Request(), crud.resourceGet_Response())

        if error:
            sys.exit(f'Error getting asset or collection: {error}')

        print(response['content'])

    except Exception as e:
        sys.exit(f'Error getting asset or collection: {e}')

    return 0


def configure(subparsers):
    parser_get = subparsers.add_parser(
        'get', help='get type[/name[/version]]: Get a resource.')

    parser_get.add_argument('uuid', type=str,
                            help=f'UUID of the resource to get.')

    parser_get.set_defaults(func=run)
