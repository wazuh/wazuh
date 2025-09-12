import sys
import json
from google.protobuf.json_format import ParseDict
from google.protobuf.struct_pb2 import Value
from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.kvdb_pb2 as ekvdb


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)
    request = ekvdb.dbPut_Request()
    request.name = args['name']
    request.entry.key = args['key']
    jstr_value = args['value']

    # Check if the value is a JSON
    value = Value()
    try:
        # Try to parse the value as a JSON
        ParseDict(json.loads(jstr_value), value)
    except json.JSONDecodeError:
        # If it fails, set the value as a string
        value.string_value = jstr_value

    request.entry.value.CopyFrom(value)
    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error inserting/updating the key-value pair: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(
            f'Error inserting/updating the key-value pair: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        'upsert', help='Insert or update a key-value in the database')
    parser.add_argument(
        'name', type=str, help='Name of the key-value database')
    parser.add_argument('key', type=str, help='Key of the key-value pair')
    parser.add_argument(
        'value', type=str, help='JSON value of the key-value pair (Optional)', default='null', nargs='?')

    parser.set_defaults(func=run)
