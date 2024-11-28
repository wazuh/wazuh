import sys
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.geo_pb2 as egeo


def run(args):

    # Get the params
    api_socket: str = args['api_socket']
    path: str = args['path']
    type: str = args['type']
    url: str = args['url']
    url_hash: str = args['url-hash']

    # Create API client
    client = APIClient(api_socket)

    request = egeo.DbRemoteUpsert_Request()
    request.path = path
    request.type = type
    request.dbUrl = url
    request.hashUrl = url_hash

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error upserting GeoIP database: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error upserting GeoIP database: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser_create = subparsers.add_parser(
        'remote-upsert', help='Download and update a GeoIP database from a remote URL')

    parser_create.add_argument(
        'path', type=str, help='Path to store the GeoIP database')
    parser_create.add_argument(
        'type', type=str, help='Type of the GeoIP database', choices=['asn', 'city'])
    parser_create.add_argument(
        'url', type=str, help='URL to download the GeoIP database')
    parser_create.add_argument(
        'url-hash', type=str, help='URL of the hash file to verify the GeoIP database')

    parser_create.set_defaults(func=run)
