import sys
from google.protobuf.json_format import ParseDict
from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.kvdb_pb2 as ekvdb
from shared.dumpers import dict_to_str_yml, dict_to_str_json

def export_as_object(entries: dict):
    result = {}
    for entry in entries:
        result[entry['key']] = entry['value']
    return result


def run(args):

    # Get the params
    api_socket: str = args['api_socket']
    json_output: bool = args['json']


    # Create API client
    client = APIClient(api_socket)
    request = ekvdb.dbSearch_Request()
    request.name = args['name']
    request.prefix = args['prefix']

    # 'page' and 'page_size' are optional but must be provided together
    if args['page'] is None and args['page_size'] is not None \
       or args['page'] is not None and args['page_size'] is None:
        sys.exit('Both page and page_size must be provided')
    elif args['page'] is not None and args['page_size'] is not None:
        if args['page'] < 1:
            sys.exit('The page number must be greater than 0')
        if args['page_size'] < 1:
            sys.exit('The page size must be greater than 0')
        request.page = args['page']
        request.records = args['page_size']


    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error searching the key-value database: {error}')

    # Parse the response
    parsed_response = ParseDict(response, ekvdb.dbSearch_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error searching the key-value database: {parsed_response.error}')

    # Print the response
    data : dict = response['entries'];
    if args['as_object']:
        data = export_as_object(data)

    if json_output:
        data = dict_to_str_json(data, True)
    else:
        data = dict_to_str_yml(data)

    print(data)

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        'search', help='Get filtered key-value pairs from the database')
    parser.add_argument(
        'name', type=str, help='Name of the key-value database')
    parser.add_argument('prefix', type=str,
                        help='Prefix of the key-value pair')
    parser.add_argument(
        'page', type=int, help='Page number, if want to paginate (Optional)', default=None, nargs='?')
    parser.add_argument('page_size', type=int,
                        help='Page size, if want to paginate (Optional)', default=None, nargs='?')
    parser.add_argument('-j', '--json', action='store_true',
                        help='Output in JSON format', default=False)
    parser.add_argument('--as-object', action='store_true',
                        help='Output as object (for export)', default=False)

    parser.set_defaults(func=run)
