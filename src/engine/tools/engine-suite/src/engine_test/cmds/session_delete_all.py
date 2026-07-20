import sys
import argparse
from google.protobuf.json_format import ParseDict
from shared.dumpers import dict_to_str_json

from api_communication.client import APIClient
import api_communication.proto.tester_pb2 as etester
import api_communication.proto.engine_pb2 as engine


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = etester.TableGet_Request()

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error getting session list: {error}')

    # Parse the response
    parsed_response = ParseDict(response, etester.TableGet_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error getting session list: {parsed_response.error}')

    # Create the list of sessions to delete
    sessions_to_delete = []
    for session in parsed_response.sessions:
        if args['only_engine_tests'] and not session.name.startswith('engine_test_'):
            continue
        sessions_to_delete.append(session.name)

    # Delete the sessions
    for session in sessions_to_delete:
        request = etester.SessionDelete_Request()
        request.name = session

        error, response = client.send_recv(request)
        if error:
            sys.exit(f'Error deleting session: {error}')

        parsed_response = ParseDict(response, engine.GenericStatus_Response())
        if parsed_response.status == engine.ERROR:
            print(f'Error deleting session: {parsed_response.error}')
        else:
            print(f'Session {session} deleted')


    return 0


def configure(subparsers):
    parser = subparsers.add_parser('delete-all', help='Delete all sessions')
    parser.add_argument(
        '-o', '--only-engine-tests', help='Delete the session starting with "engine_test_"', action='store_true', default=False)
    parser.set_defaults(func=run)
