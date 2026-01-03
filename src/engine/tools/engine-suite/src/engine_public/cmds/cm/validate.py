import sys
import json
from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.crud_pb2 as crud


def _read_resource_json(args) -> dict:
    raw = args.get("resource", "") or ""
    if not raw:
        raw = sys.stdin.read()

    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.exit(f"Invalid JSON input: {e.msg} (line {e.lineno}, col {e.colno})")

    if not isinstance(obj, dict):
        sys.exit("Resource must be a JSON object (top-level must be an object).")

    return obj


def run(args):
    api_socket: str = args["api_socket"]

    json_request = {
        "type": args["type"],
        "resource": _read_resource_json(args),
    }

    try:
        client = APIClient(api_socket)
        error, _ = client.jsend(
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
        "--resource",
        type=str,
        help="JSON object of the resource to validate. If omitted, it is read from stdin.",
        default="",
    )

    parser.set_defaults(func=run)
