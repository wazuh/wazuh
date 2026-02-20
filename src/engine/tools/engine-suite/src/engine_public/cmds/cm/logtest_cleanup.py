import sys
from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.tester_pb2 as tester


def run(args):
    api_socket: str = args["api_socket"]

    try:
        client = APIClient(api_socket)
        req = tester.LogtestDelete_Request()
        error, response = client.send(req, engine.GenericStatus_Response())

        if error:
            sys.exit(f"Error cleaning logtest: {error}")

    except Exception as e:
        sys.exit(f"Error cleaning logtest: {e}")

    print("Logtest session cleaned up successfully")
    return 0


def configure(subparsers):
    parser = subparsers.add_parser("logtest-cleanup", help="Cleanup logtest session + namespace")
    parser.set_defaults(func=run)
