import socket
import struct
from typing import Optional, Tuple

import json
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import Message

from api_communication.command import get_command


class APIClient:
    """Client to communicate with the Engine API socket
    """

    def __init__(self, api_socket: str):
        """Create a new API client

        Args:
            api_socket (str): Path to the API socket
        """
        self.api_socket = api_socket

    def _send(self, request: dict, client_socket) -> Optional[str]:
        """Send a request to the API socket

        Args:
            request (dict): JSON request

        Returns:
            Optional[str]: Error message if an error occurred, None otherwise
        """

        try:
            request_raw = json.dumps(request)
            payload = bytes(request_raw, 'utf-8')

            # Pack the message with the length of the payload
            sec_msg = bytearray()
            sec_msg.extend(struct.pack('<i', len(payload)))
            sec_msg.extend(payload)

            # Send the message
            client_socket.sendall(sec_msg)
        except Exception as e:
            return f'Error while sending request: {e}'
        else:
            return None

    def _receive_all(self, sock, size: int) -> Optional[bytes]:
        data = b""
        while len(data) < size:
            packet = sock.recv(size - len(data))
            if not packet:
                return None
            data += packet
        return data

    def _receive(self, client_socket) -> Tuple[Optional[str], dict]:
        """Receive a response from the API socket

        Returns:
            Tuple[Optional[str], dict]: Error message if an error occurred, response otherwise
        """

        try:
            # Receive the 4 bytes of message length
            response_length_bytes = client_socket.recv(4)

            # Unpack all 4 bytes to get the length of the response message
            response_length = struct.unpack('<i', response_length_bytes)[0]

            # Receive the complete response using the receive_al function
            response = self._receive_all(client_socket, response_length)

            # Decode and convert the response to a readable string (if necessary)
            if not response:
                return 'No response received', {}

            response_str = response.decode("utf-8")

            # Convert response to JSON
            response_json = json.loads(response_str)
        except Exception as e:
            return f'Error while receiving response: {e}', {}
        else:
            return None, response_json

    def send_recv(self, message: Message) -> Tuple[Optional[str], dict]:
        """Send a message to the API socket and receive the response

        Args:
            message (Message): Proto message to send

        Returns:
            Tuple[Optional[str], Message]: Error message if an error occurred, response json otherwise
        """

        # Prepare the request
        try:
            params = MessageToDict(message)
        except Exception as e:
            return f'Error while converting message to dict: {e}', {}

        err, command = get_command(message)
        if err:
            return err, {}

        request = {
            'version': 1,
            'command': command,
            'origin': {'name': 'engine-integration-test', 'module': 'engine-integration-test'},
            'parameters': params
        }

        # Start the connection
        try:
            client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client_socket.connect(self.api_socket)
        except Exception as e:
            return f'Error while connecting to API socket{self.api_socket}: {e}', {}

        # Send the request
        err = self._send(request, client_socket)
        if err:
            client_socket.close()
            return err, {}

        # Receive the response
        err, response = self._receive(client_socket)
        if err:
            client_socket.close()
            return err, {}

        client_socket.close()

        if 'code' in response and response['code'] != 0:
            return f'Protocol Error {response["code"]}', {}

        # Obtain the response message
        return None, response['data']
