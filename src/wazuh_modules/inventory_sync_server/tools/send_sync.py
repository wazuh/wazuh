#!/usr/bin/env python3
"""
Manual/end-to-end sender for the inventory_sync_server UDS endpoint.

Speaks the same bytes remoted's AsioUdsHttpClient puts on the wire (HTTP/1.1 over an AF_UNIX
stream, Content-Length delimited, Connection: close), so it exercises the real server rather than
an approximation of it.

Standard library only -- no requests, no requests-unixsocket -- so it runs on the manager's own
embedded interpreter without installing anything.

Examples:
    # Liveness probe
    ./send_sync.py --health

    # One 1 KiB junk payload to the sync endpoint (expects 400: not a FullSession)
    ./send_sync.py --size 1024

    # 100 payloads in sequence, to watch the throttled log line aggregate
    ./send_sync.py --size 4096 --repeat 100

    # Unknown route (expects 404) and wrong verb (expects 405 with an Allow header)
    ./send_sync.py --bad-route
    ./send_sync.py --method PUT

    # Over the body cap (expects 413)
    ./send_sync.py --size 33554432

Run it from the manager's home directory so the default relative socket path resolves, or pass
--socket with an absolute path.
"""

import argparse
import http.client
import os
import socket
import sys
import time

DEFAULT_SOCKET = "queue/sockets/inventory-sync.sock"
DEFAULT_PATH = "/stateful"
# Mirrors invsync::endpoints::sync::path(). Source of truth:
# src/wazuh_modules/inventory_sync_server/src/endpoints/syncEndpoint.hpp
HEALTH_PATH = "/"


class UnixHTTPConnection(http.client.HTTPConnection):
    """http.client over an AF_UNIX stream socket."""

    def __init__(self, socket_path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


def send_once(socket_path, method, path, body, content_type, timeout, agent_id=""):
    """Returns (status, reason, headers, body) or raises."""
    connection = UnixHTTPConnection(socket_path, timeout=timeout)
    try:
        headers = {"Host": "localhost", "Connection": "close"}
        if content_type:
            headers["Content-Type"] = content_type
        if agent_id:
            # What remoted sets from the identity it authenticated; without it /stateful is a 400.
            headers["X-Wazuh-Agent-Id"] = agent_id
        # http.client sets Content-Length from the body automatically.
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.reason, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(
        description="Send HTTP/1.1 requests to inventory_sync_server over its Unix domain socket.")
    parser.add_argument("--socket", default=DEFAULT_SOCKET,
                        help=f"socket path, relative to the current directory (default: {DEFAULT_SOCKET})")
    parser.add_argument("--path", default=None, help=f"request target (default: {DEFAULT_PATH})")
    parser.add_argument("--method", default="POST", help="HTTP verb (default: POST)")
    parser.add_argument("--size", type=int, default=64, help="payload size in bytes (default: 64)")
    parser.add_argument("--repeat", type=int, default=1, help="how many requests to send (default: 1)")
    parser.add_argument("--content-type", default="application/octet-stream",
                        help="Content-Type header; pass an empty string to omit it, as the peer does")
    parser.add_argument("--timeout", type=float, default=30.0, help="per-request timeout in seconds")
    parser.add_argument("--agent-id", default="1",
                        help="X-Wazuh-Agent-Id header value (default: 1; pass an empty string to omit the header)")
    parser.add_argument("--health", action="store_true", help="probe GET / instead (expects 200)")
    parser.add_argument("--bad-route", action="store_true", help="target an unknown path (expects 404)")
    parser.add_argument("--quiet", action="store_true", help="only print a summary")
    args = parser.parse_args()

    if not os.path.exists(args.socket):
        print(f"error: no socket at '{args.socket}'.", file=sys.stderr)
        print("       Run this from the manager's home directory, or pass --socket with a full path.",
              file=sys.stderr)
        print("       If the module is running, check that it logged 'listening on'.", file=sys.stderr)
        return 2

    if args.health:
        method, path, body = "GET", HEALTH_PATH, b""
    elif args.bad_route:
        method, path, body = args.method, "/no-such-endpoint", b"x" * args.size
    else:
        method = args.method
        path = args.path if args.path is not None else DEFAULT_PATH
        body = b"x" * args.size

    statuses = {}
    started = time.monotonic()

    for index in range(args.repeat):
        try:
            status, reason, headers, response_body = send_once(
                args.socket, method, path, body, args.content_type, args.timeout, args.agent_id)
        except Exception as error:  # noqa: BLE001 - a manual tool should report, not traceback
            print(f"request {index + 1}: failed: {error}", file=sys.stderr)
            statuses["error"] = statuses.get("error", 0) + 1
            continue

        statuses[status] = statuses.get(status, 0) + 1
        if not args.quiet:
            print(f"request {index + 1}: {status} {reason}")
            if "Allow" in headers:
                print(f"  Allow: {headers['Allow']}")
            if response_body:
                print(f"  body: {response_body.decode('utf-8', 'replace')}")

    elapsed = time.monotonic() - started
    print(f"\n{args.repeat} request(s) in {elapsed:.2f}s: "
          + ", ".join(f"{count} x {status}" for status, count in sorted(statuses.items(), key=str)))

    return 0 if all(isinstance(s, int) and 200 <= s < 300 for s in statuses) else 1


if __name__ == "__main__":
    sys.exit(main())
