# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import os.path
import socket
from json import dumps, loads
from struct import pack, unpack

from wazuh import common
from wazuh.core.exception import WazuhException, WazuhInternalError

SOCKET_COMMUNICATION_PROTOCOL_VERSION = 1


class WazuhSocket:
    MAX_SIZE = 65536

    def __init__(self, path):
        self.path = path
        self._connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __enter__(self):
        return self

    def _connect(self):
        try:
            self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.s.connect(self.path)
        except FileNotFoundError:
            raise WazuhInternalError(1013, extra_message=os.path.basename(self.path))
        except ConnectionRefusedError:
            raise WazuhInternalError(1121, extra_message=f"Socket '{os.path.basename(self.path)}' cannot receive "
                                                         "connections")
        except Exception as e:
            raise WazuhException(1013, str(e))

    def close(self):
        self.s.close()

    def send(self, msg_bytes, header_format="<I"):
        if not isinstance(msg_bytes, bytes):
            raise WazuhException(1105, "Type must be bytes")

        try:
            sent = self.s.send(pack(header_format, len(msg_bytes)) + msg_bytes)
            if sent == 0:
                raise WazuhException(1014, "Number of sent bytes is 0")
            return sent
        except Exception as e:
            raise WazuhException(1014, str(e))

    def receive(self, header_format="<I", header_size=4):

        try:
            size = unpack(header_format, self.s.recv(header_size, socket.MSG_WAITALL))[0]
            return self.s.recv(size, socket.MSG_WAITALL)
        except Exception as e:
            raise WazuhException(1014, str(e))


class WazuhSocketJSON(WazuhSocket):
    MAX_SIZE = 65536

    def __init__(self, path):
        WazuhSocket.__init__(self, path)

    def send(self, msg, header_format="<I"):
        return WazuhSocket.send(self, msg_bytes=dumps(msg).encode(), header_format=header_format)

    def receive(self, header_format="<I", header_size=4, raw=False):
        response = loads(WazuhSocket.receive(self, header_format=header_format, header_size=header_size).decode())
        if not raw:
            if 'error' in response.keys():
                if response['error'] != 0:
                    raise WazuhException(response['error'], response['message'], cmd_error=True)
            return response['data']
        else:
            return response


class WazuhAsyncProtocol(asyncio.Protocol):
    """Wazuh implementation of asyncio.Protocol class."""

    def __init__(self, loop):
        self.loop = loop
        self.on_data_received = loop.create_future()
        self.data = None
        self.closed = False

    def connection_lost(self, exc):
        self.closed = True

    def data_received(self, data: bytes) -> None:
        self.data = data
        self.on_data_received.set_result(True)

    def get_data(self) -> bytes:
        if self.data:
            aux = self.data
            self.data = None
            self.on_data_received = self.loop.create_future()
            return aux


class WazuhAsyncSocket:
    """Handler class to connect and operate with sockets asynchronously."""

    def __init__(self):
        self.reader = None
        self.writer = None

    async def connect(self, path_to_socket: str):
        """Establish connection with the socket and creates both Transport
        and Protocol objects to operate with it.

        Parameters
        ----------
        path_to_socket : str
            Path where the socket is located.

        Raises
        ------
        WazuhException(1013)
            If the connection with the socket can't be established.
        """
        try:
            self.reader, self.writer = await asyncio.open_unix_connection(path_to_socket)

        except (OSError, FileNotFoundError, AttributeError, ValueError) as exc:
            raise WazuhException(1013, str(exc)) from exc

    def close(self):
        """Close connection with the socket and the Transport objects."""
        self.writer.close()

    async def send(self, msg_bytes: bytes, header_format: str = "<I"):
        """Add a header to the message and sends it to the socket. Returns that message.

        Parameters
        ----------
        msg_bytes : bytes
            A set of bytes to be send.
        header_format : str, optional
            Format of the header to be packed in the message. Default value is big-endian.

        Raises
        ------
        WazuhException(1014)

        """
        if not isinstance(msg_bytes, bytes):
            raise WazuhException(1014, "Type must be bytes")
        elif len(msg_bytes) == 0:
            raise WazuhException(1014, "Number of sent bytes is 0")

        try:
            self.writer.write(pack(header_format, len(msg_bytes)) + msg_bytes)
            await self.writer.drain()
        except (ConnectionResetError, OSError) as exc:
            raise WazuhException(1014, "Socket connection was closed") from exc

    async def receive(self, header_format: str ="<I", header_size: int = 4) -> bytes:
        """Return the content of the socket.

        Parameters
        ----------
        header_format : str, optional
            Format of the header to be packed in the message. Default value is big-endian.

        header_size : int
            Size of the header to be extracted from the message received.

        Raises
        ------
        WazuhException(1014)
            If there is no connection with the socket.

        Returns
        -------
        bytes
            Bytes received.
        """
        try:
            header = await self.reader.read(header_size)
            size = unpack(header_format, header)[0]
            return await self.reader.read(size)
        except Exception as exc:
            raise WazuhException(1014, str(exc)) from exc


class WazuhAsyncSocketJSON(WazuhAsyncSocket):
    """Handler class to connect and operate asynchronously with a socket using
    messages in JSON format."""

    async def send(self, msg_bytes: str, header_format: str = "<I") -> bytes:
        """Convert the message from JSON format to bytes and send it to the socket.
        Returns that message.

        Parameters
        ----------
        msg : str
            The message in JSON format.
        header_format : str, optional
            Format of the header to be packed in the message.

        Returns
        -------
        bytes
            Bytes sent.
        """
        return await super().send(msg_bytes=dumps(msg_bytes).encode(), header_format=header_format)

    async def receive_json(self, header_format: str ="<I", header_size: int = 4) -> dict:
        """Get the data from the socket and convert it to JSON.

        Parameters
        ----------
        header_size : int
            Size of the header to be extracted from the message received.

        Raises
        ------
        WazuhException
            If the message obtained from the socket was an error message.

        Returns
        -------
        dict
            Data received.
        """
        response = await super().receive(header_format=header_format, header_size=header_size)
        response = loads(response.decode())
        if 'error' in response.keys():
            if response['error'] != 0:
                raise WazuhException(response['error'], response['message'], cmd_error=True)
        return response['data']


def create_wazuh_socket_message(origin=None, command=None, parameters=None):
    communication_protocol_message = {'version': SOCKET_COMMUNICATION_PROTOCOL_VERSION}

    if origin:
        communication_protocol_message['origin'] = origin

    if command:
        communication_protocol_message['command'] = command

    if parameters:
        communication_protocol_message['parameters'] = parameters

    return communication_protocol_message
