import socket
import struct
import httpx
import json
from typing import Optional, Tuple

from google.protobuf.json_format import MessageToDict
from google.protobuf.json_format import ParseDict
from google.protobuf.message import Message

from api_communication.endpoints import get_endpoint
from api_communication.proto.engine_pb2 import GenericStatus_Response
from api_communication.proto.engine_pb2 import ReturnStatus


DEFAULT_TIMEOUT = 10

class APIClient:
    """Client to communicate with the Engine API socket
    """

    def __init__(self, api_socket: str):
        """Create a new API client

        Args:
            api_socket (str): Path to the API socket
        """
        self.api_socket = api_socket
        self.transport = httpx.HTTPTransport(uds=api_socket)

    def _set_error_msg(self, error) -> str:
        """Set the error message

        Args:
            error (Exception): Error object

        Returns:
            str: Error message
        """

        msg = "Unknown HTTP error"

        # TimeoutException
        if isinstance(error, httpx.TimeoutException):
            if isinstance(error, httpx.ConnectTimeout):
                msg = 'Timed out while connecting host'
            if isinstance(error, httpx.ReadTimeout):
                msg = 'Timed out while receiving data from the host'
            if isinstance(error, httpx.WriteTimeout):
                msg = 'Timed out while sending data to the host'

        # NetworkError
        if isinstance(error, httpx.NetworkError):
            if isinstance(error, httpx.ConnectError):
                msg = 'Failed to establish a connection'
            if isinstance(error, httpx.ReadError):
                msg = 'Failed to receive data from the network'
            if isinstance(error, httpx.WriteError):
                msg = 'Failed to send data through the network'
            if isinstance(error, httpx.CloseError):
                msg = 'Failed to close the connection'

        msg += f': {error}'
        return msg

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

        err, endpoint = get_endpoint(message)
        if err:
            return err, {}

        body = json.dumps(params)
        header = {'Content-Type': 'text/plain'}

        # Send the request
        try:
            client = httpx.Client(transport=self.transport)
            response = client.post(
                f'http://localhost/{endpoint}', data=body, headers=header, timeout=DEFAULT_TIMEOUT)

            if response.status_code != 200:
                # Check if the error contains a message
                if not response.text:
                    return f'Error {response.status_code} while sending request', {}
            return None, response.json()

        except httpx.HTTPError as e:
            return f'HTTP error: {self._set_error_msg(e)}', {}

        except Exception as e:
            return f'Unknown error: {e}', {}

    def jsend(self, json_body: dict, reqProtoMsg: Message, resProtoMsg: Message = GenericStatus_Response()) -> Tuple[Optional[str], dict]:
        """Send a message to the API socket and receive the response

        Args:
            json_body (dict): JSON message to send
            reqProtoMsg (Message): Proto message type to send
            resProtoMsg (Message): Proto message type to receive

        Returns:
            Tuple[Optional[str], Message]: Error message if an error occurred or the response is an error, response json otherwise
        """

        # Prepare the request
        body = json.dumps(json_body)
        header = {'Content-Type': 'text/plain'}
        err, endpoint = get_endpoint(reqProtoMsg)

        if err:
            return f'Cannot get endpoint from message: {err}', {}

        # Send the request
        response: httpx.Response = None
        try:
            client = httpx.Client(transport=self.transport)
            response = client.post(
                f'http://localhost/{endpoint}', data=body, headers=header)

        except httpx.HTTPError as e:
            return f'HTTP error: {self._set_error_msg(e)}', {}

        except Exception as e:
            return f'Unknown error: {e}', {}

        # Error from server
        if response.status_code != 200:
            # Check if the error contains a message
            if not response.text:
                return f'Error {response.status_code} while sending request', {}

        # Response from server endpoint handler
        try:
            json_response = json.loads(response.text)
            protoRes = ParseDict(json_response, resProtoMsg)
        except Exception as e:
            return f'Error while parsing response: {e}', {}

        # Treat response as a generic status response
        if protoRes.status != ReturnStatus.OK:
            return protoRes.error, {}

        # Return the response
        return None, json_response

    def send(self, reqProtoMsg: Message, resProtoMsg: Message = GenericStatus_Response()) -> Tuple[Optional[str], dict]:
        """Send a message to the API socket and receive the response

        Args:
            reqProtoMsg (Message): Proto message to send
            resProtoMsg (Message): Proto message to receive

        Returns:
            Tuple[Optional[str], Message]: Error message if an error occurred, response json otherwise
        """

        try:
            json_body = MessageToDict(reqProtoMsg)
        except Exception as e:
            return f'Error while converting message to dict: {e}', {}

        return self.jsend(json_body, reqProtoMsg, resProtoMsg)
