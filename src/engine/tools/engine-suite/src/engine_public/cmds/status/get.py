import sys
import json
from api_communication.client import APIClient
import api_communication.proto.status_pb2 as status
from shared.dumpers import dict_to_str_yml


def run(args):
    api_socket: str = args["api_socket"]

    try:
        client = APIClient(api_socket)
        req = status.StatusGet_Request()
        error, response = client.send(req, status.StatusGet_Response())

        if error:
            sys.exit(f"Error getting engine status: {error}")

        # Display the engine readiness status
        if args["output_format"] == "json":
            print(json.dumps(response, indent=4))
        else:
            print(dict_to_str_yml(response))

    except Exception as e:
        sys.exit(f"Error getting engine status: {e}")

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        "get",
        help="Get the engine readiness status (spaces, IOC and geo databases)"
    )
    parser.add_argument(
        "-f",
        "--output-format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Output format (text or json). Default: text"
    )
    parser.set_defaults(func=run)
