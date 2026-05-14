#!/usr/bin/env python3
"""
Send messages to the main Wazuh queue (analysisd/agentd).
Created: November 1, 2016

Usage:
    sendmsg.py [-L] [message]
    echo "msg" | sendmsg.py

Standard message format: <id>:<location>:<log>
"""

import argparse
import sys
from socket import socket, AF_UNIX, SOCK_DGRAM, SO_SNDBUF, SOL_SOCKET

ADDR = '/var/ossec/queue/sockets/queue'
BLEN = 212992


def expand_socket_buffer(sock):
    oldbuf = sock.getsockopt(SOL_SOCKET, SO_SNDBUF)
    if oldbuf < BLEN:
        sock.setsockopt(SOL_SOCKET, SO_SNDBUF, BLEN)
        newbuf = sock.getsockopt(SOL_SOCKET, SO_SNDBUF)
        print(f"INFO: Buffer expanded from {oldbuf} to {newbuf}")


def send_message(sock, message):
    sock.send(message.encode())


def send_loop(sock, message):
    count = 1
    try:
        while True:
            send_message(sock, message)
            count += 1
    except BaseException as e:
        print(e)
        print(f"Messages: {count}\nBytes: {count * len(message)}")


def get_message(args):
    if args.message:
        return ' '.join(args.message)
    elif not sys.stdin.isatty():
        return sys.stdin.read().strip()
    else:
        print("No message provided. Use argument or pipe input.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Send messages to the main Wazuh queue (analysisd/agentd)."
    )
    parser.add_argument(
        '-L', action='store_true',
        help='Send the message in a loop until interrupted'
    )
    parser.add_argument(
        'message', nargs='*',
        help='Message to send (standard format: <id>:<location>:<log>)'
    )
    args = parser.parse_args()

    message = get_message(args)

    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(ADDR)
    expand_socket_buffer(sock)

    if args.L:
        send_loop(sock, message)
    else:
        send_message(sock, message)

    sock.close()


if __name__ == "__main__":
    main()
