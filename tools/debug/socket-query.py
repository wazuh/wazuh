#! /usr/bin/env python3
# November 18, 2020

import argparse
from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
from sys import stdin, stdout

DESCRIPTION = """
Socket Query Tool for Wazuh modules

Examples:
    echo -n '{"command":"getconfig","parameters":{"section":"internal"}}' | \\
    ./socket-query.py /var/ossec/queue/sockets/analysis

This tool allows you to send queries to Wazuh module control sockets.
"""


def send_query(sock_path, query_bytes):
    with socket(AF_UNIX, SOCK_STREAM) as sock:
        sock.connect(sock_path)
        payload = pack(f"<I{len(query_bytes)}s", len(query_bytes), query_bytes)
        sock.sendall(payload)
        length = unpack("<I", sock.recv(4))[0]
        response = sock.recv(length)
        return response


def main():
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "socket",
        help="Path to the Wazuh module control socket"
    )
    args = parser.parse_args()

    sock_path = args.socket
    query_bytes = stdin.buffer.read()
    response = send_query(sock_path, query_bytes)
    stdout.buffer.write(response)
    if stdout.isatty():
        print("")


if __name__ == "__main__":
    main()
