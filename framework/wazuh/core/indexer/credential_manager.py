"""
Keystore Client - SizeHeaderProtocol format
"""

import json
from wazuh.core.wazuh_socket import WazuhSocket
from wazuh.core.common import KEY_STORE_SOCKET


class KeystoreClient:
    def __init__(self, logger=None):
        self.socket_path = KEY_STORE_SOCKET
        self.socket = None
        self.logger = logger
        self.connect()

    def connect(self):
        self.socket = WazuhSocket(self.socket_path)
        self.logger.debug("Connected!")

    def disconnect(self):
        if self.socket:
            self.socket.close()
            self.socket = None

    def send_query(self, query: str):
        """
        Send query and receive response using WazuhSocket
        """
        if not self.socket:
            raise RuntimeError("Socket not connected")

        self.logger.debug(f"Query executed: {query}")

        self.socket.send(query.encode("utf-8"))
        response_bytes = self.socket.receive()

        response = response_bytes.decode("utf-8")
        self.logger.debug(f"And the response is: {response}")

        return json.loads(response)

    def put(self, cf, key, value):
        return self.send_query(f"PUT|{cf}|{key}|{value}")

    def get(self, cf, key):
        return self.send_query(f"GET|{cf}|{key}")

    def delete(self, cf, key):
        return self.send_query(f"DELETE|{cf}|{key}")
