#!/usr/bin/env python3
# MITM tool for Wazuh queue socket
# June 21, 2022

import argparse
from socket import socket, AF_UNIX, SOCK_DGRAM, SO_SNDBUF, SOL_SOCKET
from sys import stderr, exit
from os import unlink, chmod

ADDR = '/var/ossec/queue/sockets/queue'
BLEN = 212992
INPUT_LEN = 65536


def connect(addr=ADDR, blen=BLEN):
    """Connect to the Wazuh queue socket as a client."""
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(addr)
    oldbuf = sock.getsockopt(SOL_SOCKET, SO_SNDBUF)
    if oldbuf < blen:
        sock.setsockopt(SOL_SOCKET, SO_SNDBUF, blen)
        newbuf = sock.getsockopt(SOL_SOCKET, SO_SNDBUF)
        print(
            f"INFO: Output buffer expended from {oldbuf} to {newbuf}", file=stderr)
    return sock


def listen(addr=ADDR, blen=BLEN):
    """Bind and listen on the Wazuh queue socket."""
    try:
        unlink(addr)
    except FileNotFoundError:
        pass
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.bind(addr)
    oldbuf = sock.getsockopt(SOL_SOCKET, SO_SNDBUF)
    if oldbuf < blen:
        sock.setsockopt(SOL_SOCKET, SO_SNDBUF, blen)
        newbuf = sock.getsockopt(SOL_SOCKET, SO_SNDBUF)
        print(
            f"INFO: Input buffer expended from {oldbuf} to {newbuf}", file=stderr)
    chmod(addr, 0o666)
    return sock


def mitm_loop(input_sock, output_sock, input_len=INPUT_LEN):
    """Intercept and forward messages between sockets."""
    print("INFO: Queue hacked. Now restart the rest of daemons.", file=stderr)
    try:
        while True:
            buffer = input_sock.recv(input_len)
            print(buffer.decode(encoding="UTF-8", errors="replace"))
            output_sock.send(buffer)
    except KeyboardInterrupt:
        print("INFO: Please restart the manager.", file=stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Intercept communication between Wazuh daemons and the main queue socket.",
        epilog="This tool is intended for debugging and analysis purposes only.",
        add_help=True
    )
    args = parser.parse_args()

    try:
        output_sock = connect()
    except ConnectionRefusedError:
        print("ERROR: Cannot connect to Analysisd.", file=stderr)
        exit(1)

    input_sock = listen()
    mitm_loop(input_sock, output_sock)


if __name__ == "__main__":
    main()
