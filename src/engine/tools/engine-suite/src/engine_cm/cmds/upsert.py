import sys
from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.crud_pb2 as crud


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    json_request = dict()
    json_request['space'] = args['space']
    json_request['type'] = args['type']

    content = args['content']
    # Read all content from stdin
    if not content:
        content = sys.stdin.read()

    json_request['ymlContent'] = content

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.jsend(
            json_request, crud.resourcePost_Request(), engine.GenericStatus_Response())

        if error:
            sys.exit(f'Error upserting resource: {error}')

    except Exception as e:
        sys.exit(f'Error upserting resource: {e}')

    return 0


def configure(subparsers):
    parser_upsert = subparsers.add_parser(
        'upsert', help='Upsert a new resource.')

    parser_upsert.add_argument('type', type=str,
                               help=f'Type of resource to upsert.')

    parser_upsert.add_argument('-c', '--content', type=str, default='',
                               help='Content of the item, can be passed as argument or '
                               'redirected from a file using the "|" operator or the "<" '
                               'operator.')

    parser_upsert.set_defaults(func=run)
