# validate.py
import sys
from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.crud_pb2 as crud


def run(args):
    # Get the params
    api_socket: str = args["api_socket"]

    json_request = dict()
    json_request["type"] = args["type"]

    content = args["jsonContent"]
    # Read all content from stdin
    if not content:
        content = sys.stdin.read()

    json_request["jsonContent"] = content

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.jsend(
            json_request,
            crud.resourceValidate_Request(),
            engine.GenericStatus_Response()
        )

        if error:
            sys.exit(f"Error validating resource: {error}")

    except Exception as e:
        sys.exit(f"Error validating resource: {e}")

    return 0


def configure(subparsers):
    parser = subparsers.add_parser("validate", help="Validate a resource payload")
    parser.add_argument("type", type=str, help="Type of resource to validate.")
    parser.add_argument(
        "-c",
        "--jsonContent",
        type=str,
        help="JSON content of the resource to validate. If omitted, it is read from stdin.",
        default="",
    )

    parser.set_defaults(func=run)
