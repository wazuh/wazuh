import sys
import json
from google.protobuf.json_format import ParseDict, MessageToDict

from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.geo_pb2 as egeo


def run(args):

    # Get the params
    api_socket: str = args['api_socket']
    ip: str = args['ip']

    # Create API client
    client = APIClient(api_socket)

    request = egeo.DbGet_Request()
    request.ip = ip

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error getting GeoIP database information: {error}')

    # Parse the response
    parsed_response = ParseDict(response, egeo.DbGet_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error getting GeoIP database information: {parsed_response.error}')

    # Convert Struct to dict and print as JSON
    data_dict = MessageToDict(parsed_response.data, preserving_proto_field_name=True)
    print(json.dumps(data_dict, indent=2))

    return 0


def configure(subparsers):
    parser_create = subparsers.add_parser(
        'get', help='Get information about a GeoIP database')

    parser_create.add_argument(
        'ip', type=str, help='IP of location to the GeoIP database to get information about')

    parser_create.set_defaults(func=run)
