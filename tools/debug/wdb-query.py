#! /usr/bin/python3
# September 16, 2019
# Rev 1 - February 19, 2024
# Rev 2 - July 25, 2025

# Syntax: wdb-query.py [WORKERS] [-h]

import argparse
from select import select
from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
from sys import stdin
from json import dumps, loads
from json.decoder import JSONDecodeError

WDB_PATH = '/var/ossec/queue/db/wdb'
DEFAULT_WORKERS = 8
STDIN_FILENO = stdin.fileno()


def db_connect():
    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(WDB_PATH)
    return sock


def db_send(sock, query):
    msg = query.encode()
    sock.send(pack("<I{0}s".format(len(msg)), len(msg), msg))


def db_recv(sock):
    length = unpack("<I", sock.recv(4))[0]
    return sock.recv(length).decode(errors='ignore')


def pretty_print(payload):
    if payload.startswith('ok '):
        try:
            data = loads(payload[3:])
            response = dumps(data, indent=4)
        except JSONDecodeError:
            response = payload[3:]
    else:
        response = payload
    print(response)


class Pool:
    def __init__(self, length):
        self._length = length
        self._idle = {db_connect() for _ in range(length)}
        self._files = {STDIN_FILENO} | self._idle
        self._pending = 0

    def poll_input(self):
        readers, _, _ = select(self._files, [], [])
        for fd in readers:
            yield fd
            if fd != STDIN_FILENO:
                self._idle.add(fd)

    def poll_idle(self):
        try:
            return self._idle.pop()
        except KeyError:
            return None

    def pending(self):
        return self._length - len(self._idle)

    def lock_stdin(self):
        self._files.discard(STDIN_FILENO)

    def unlock_stdin(self):
        self._files.add(STDIN_FILENO)


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Concurrent query to Wazuh DB. "
            "Queries are read from stdin, one per line."
        ),
        usage="wdb-query.py [WORKERS] [-h]"
    )
    parser.add_argument(
        'workers', nargs='?', type=int, default=DEFAULT_WORKERS,
        help='Number of concurrent connections (default: %(default)s)'
    )
    return parser.parse_args()


def main():
    args = parse_args()
    pool = Pool(args.workers)
    active = True

    while active or pool.pending() > 0:
        any_socket = False

        if pool.pending() == args.workers:
            pool.lock_stdin()

        for fd in pool.poll_input():
            if fd == STDIN_FILENO:
                line = stdin.readline()
                if line:
                    sock = pool.poll_idle()
                    db_send(sock, line.rstrip())
                else:
                    active = False
                    pool.lock_stdin()
            else:
                payload = db_recv(fd)
                pretty_print(payload)
                any_socket = True

        if active and any_socket:
            pool.unlock_stdin()


if __name__ == '__main__':
    main()
