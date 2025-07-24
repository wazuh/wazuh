#! /usr/bin/python3
# September 16, 2019
# Rev 1 - February 19, 2024

# Syntax: wdb-query.py [WORKERS]

# Import necessary modules for socket communication, JSON handling, and command-line interaction
from select import select
from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
from sys import argv, exit, stdin
from json import dumps, loads
from json.decoder import JSONDecodeError

# Set constants for input file descriptor, Wazuh DB socket path, and default worker count
STDIN_FILENO = stdin.fileno()
WDB_PATH = '/var/ossec/queue/db/wdb'
DEFAULT_WORKERS = 8

# Create and return a Unix socket connection to the Wazuh DB
def db_connect():
    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(WDB_PATH)
    return sock

# Encode and send the query to Wazuh DB over the given socket using length-prefixed format
def db_send(sock, query):
    msg = query.encode()
    sock.send(pack("<I{0}s".format(len(msg)), len(msg), msg))

# Receive and decode the response from Wazuh DB using the expected 4-byte length prefix
def db_recv(sock):
    length = unpack("<I", sock.recv(4))[0]
    return sock.recv(length).decode(errors='ignore')

# Format and print Wazuh DB response payload as pretty JSON if it's a valid 'ok' message
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
    # Initialize the Pool with a set of Wazuh DB socket connections and track file descriptors
    def __init__(self, length):
        self._length = length
        self._idle = {db_connect() for i in range(length)}
        self._files = {STDIN_FILENO} | self._idle
        self._pending = 0

    # Yield readable file descriptors and re-add socket connections to the idle pool
    def poll_input(self):
        readers, _, _ = select(self._files, [], [])

        for fd in readers:
            yield fd

            if fd != STDIN_FILENO:
                self._idle.add(fd)

    # Retrieve and remove an idle socket connection, or return None if none are available
    def poll_idle(self):
        try:
            x = self._idle.pop()
            return x
        except KeyError:
            return None

    # Return the number of active (non-idle) socket connections currently in use
    def pending(self):
        return self._length - len(self._idle)

    # Prevent further reading from standard input by removing it from the monitored file set
    def lock_stdin(self):
        try:
            self._files.remove(STDIN_FILENO)
        except KeyError:
            pass

    # Re-enable reading from standard input by adding it back to the monitored file set
    def unlock_stdin(self):
        self._files.add(STDIN_FILENO)


if __name__ == '__main__':
    # Initialize the worker pool with user-specified or default number of workers
    workers = int(argv[1]) if len(argv) > 1 else DEFAULT_WORKERS
    pool = Pool(workers)
    active = True

    # Main loop to handle input from standard input and Wazuh DB responses
    while active or pool.pending() > 0:
        any_socket = False

        if pool.pending() == workers:
            # All workers busy, we cannot consume stdin
            pool.lock_stdin()

        # Poll for input from standard input and Wazuh DB sockets
        for fd in pool.poll_input():
            if fd == STDIN_FILENO:
                line = stdin.readline()

                # If we read a line from stdin, send it to the Wazuh DB
                if line:
                    sock = pool.poll_idle()
                    db_send(sock, line.rstrip())
                else:
                    active = False
                    pool.lock_stdin()
            # If we read from a Wazuh DB socket, receive and print the response
            else:
                payload = db_recv(fd)
                pretty_print(payload)
                any_socket = True

        # If there are active sockets and we have read from any, re-enable stdin reading
        if active and any_socket:
            pool.unlock_stdin()
