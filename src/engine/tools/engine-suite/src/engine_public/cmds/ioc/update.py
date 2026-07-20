import sys
import os
import hashlib
from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.ioc_pb2 as ioc


def _calculate_md5(file_path: str) -> str:
    """Calculate MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        sys.exit(f"Error calculating file hash: {e}")


def run(args):
    api_socket: str = args["api_socket"]
    file_path: str = args["path"]

    # Validate file exists
    if not os.path.isfile(file_path):
        sys.exit(f"Error: File not found: {file_path}")

    # Calculate hash if not provided or if auto-hash is requested
    if args.get("hash"):
        file_hash = args["hash"]
    else:
        print(f"Calculating MD5 hash of {file_path}...")
        file_hash = _calculate_md5(file_path)
        print(f"Hash: {file_hash}")

    # Create request

    try:
        client = APIClient(api_socket)
        req = ioc.UpdateIoc_Request(path=file_path, hash=file_hash)
        error, response = client.send(
            req,
            engine.GenericStatus_Response()
        )

        if error:
            sys.exit(f"Error updating IOCs: {error}")

        # Check if there's a message in the response (e.g., "already up to date")
        if response and 'error' in response and response['error']:
            print(response['error'])
        else:
            print("IOC synchronization scheduled successfully")

    except Exception as e:
        sys.exit(f"Error updating IOCs: {e}")

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        "update",
        help="Update IOCs from a ndjson file"
    )
    parser.add_argument(
        "path",
        type=str,
        help="Path to the ndjson file containing IOCs"
    )

    hash_group = parser.add_mutually_exclusive_group()
    hash_group.add_argument(
        "--hash",
        type=str,
        help="MD5 hash of the file (for optimization). If provided and matches stored hash, sync is skipped.",
        default=None
    )

    parser.set_defaults(func=run)
