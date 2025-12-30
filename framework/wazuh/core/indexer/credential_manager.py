#!/usr/bin/env python3
"""
Keystore Client - SizeHeaderProtocol format
"""

import socket
import json
import struct

SOCKET_PATH = "/var/ossec/queue/sockets/keystore"

class KeystoreClient:
    def __init__(self, socket_path=SOCKET_PATH):
        self.socket_path = socket_path
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)
        print("✓ Connected!")

    def disconnect(self):
        if self.sock:
            self.sock.close()

    def _send_with_size_header(self, data):
        """
        Send with SizeHeaderProtocol format:
        [4-byte size][body]
        """
        body_bytes = data.encode('utf-8')
        size = len(body_bytes)

        # Build message: size + body
        message = struct.pack('I', size)  # 4 bytes: size
        message += body_bytes              # N bytes: body

        self.sock.sendall(message)

    def _recv_with_size_header(self):
        """
        Receive with SizeHeaderProtocol format
        """
        self.sock.settimeout(5.0)

        # Read size (4 bytes)
        size_bytes = self._recv_exactly(4)
        size = struct.unpack('I', size_bytes)[0]

        # Read body
        body = self._recv_exactly(size)
        return body.decode('utf-8')

    def _recv_exactly(self, n):
        """Receive exactly n bytes"""
        data = bytearray()
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data.extend(chunk)
        return bytes(data)

    def send_query(self, query):
        """Send query and get response"""
        print(f"→ {query}")
        self._send_with_size_header(query)
        response = self._recv_with_size_header()
        print(f"← {response}")
        return json.loads(response)

    def put(self, cf, key, value):
        return self.send_query(f"PUT|{cf}|{key}|{value}")

    def get(self, cf, key):
        return self.send_query(f"GET|{cf}|{key}")

    def delete(self, cf, key):
        return self.send_query(f"DELETE|{cf}|{key}")
