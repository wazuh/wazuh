import sys
from api_communication.client import APIClient
import api_communication.proto.crud_pb2 as crud


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    req = crud.resourceGet_Request()
    req.space = args['space']
    req.uuid = args['uuid']
    req.asJson = True

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.send(req, crud.resourceGet_Response())

        if error:
            sys.exit(f'Error getting asset or collection: {error}')

        print(response['content'])

    except Exception as e:
        sys.exit(f'Error getting asset or collection: {e}')

    return 0


def configure(subparsers):
    parser_get = subparsers.add_parser(
        'get', help='Get a resource as JSON.')

    parser_get.add_argument('uuid', type=str,
                            help=f'UUID of the resource to get.')

    parser_get.set_defaults(func=run)
