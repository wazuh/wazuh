import sys
import json
from api_communication.client import APIClient
import api_communication.proto.ioc_pb2 as ioc
import api_communication.proto.engine_pb2 as engine
from shared.dumpers import dict_to_str_yml



def run(args):
    api_socket: str = args["api_socket"]

    try:
        client = APIClient(api_socket)
        req = ioc.GetIocState_Request()
        error, response = client.send(req, ioc.GetIocState_Response())

        if error:
            sys.exit(f"Error getting IOC state: {error}")

        # Display the IOC state (to Json)
        if args["output_format"] == "json":
            print(json.dumps(response, indent=4))
        else:
            # Display the IOC in yml
            print(dict_to_str_yml(response))


    except Exception as e:
        sys.exit(f"Error getting IOC state: {e}")

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        "state",
        help="Get the current state of the IOC manager"
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
