# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core.exception import WazuhException, WazuhInternalError
from wazuh import common
import socket
from json import dumps, loads
from struct import pack, unpack
import asyncio


class OssecSocket:

    MAX_SIZE = 65536

    def __init__(self, path):
        self.path = path
        self._connect()

    def _connect(self):
        try:
            self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.s.connect(self.path)
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


class OssecSocketJSON(OssecSocket):

    MAX_SIZE = 65536

    def __init__(self, path):
        OssecSocket.__init__(self, path)

    def send(self, msg, header_format="<I"):
        return OssecSocket.send(self, msg_bytes=dumps(msg).encode(), header_format=header_format)

    def receive(self, header_format="<I", header_size=4, raw=False):
        response = loads(OssecSocket.receive(self, header_format=header_format, header_size=header_size).decode())
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
        self.transport = None
        self.protocol = None
        self.s = None
        self.loop = None

    async def connect(self, path_to_socket):
        """Establish connection with the socket and creates both Transport and Protocol objects to operate with it.

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
            self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.s.connect(path_to_socket)
            self.loop = asyncio.get_running_loop()
            self.transport, self.protocol = await self.loop.create_connection(
                lambda: WazuhAsyncProtocol(self.loop), sock=self.s)
        except (socket.error, FileNotFoundError) as e:
            raise WazuhException(1013, str(e))
        except (AttributeError, ValueError, OSError) as e:
            self.s.close()
            raise WazuhException(1013, str(e))

    def is_connection_lost(self):
        return self.transport.is_closing() or self.protocol.closed

    async def close(self):
        """Close connection with the socket and the Transport objects."""
        self.s.close()
        if not self.transport.is_closing():
            self.transport.close()

    async def send(self, msg_bytes, header_format=None):
        """Add a header to the message and sends it to the socket. Returns that message.

        Parameters
        ----------
        msg_bytes : byte
            A set of bytes to be send.
        header_format : str, optional
            Format of the header to be packed in the message.

        Raises
        ------
        WazuhException(1105)
            If the `msg_bytes` type is not bytes.
        WazuhException(1014)
            If the message length was 0.
        """
        if not isinstance(msg_bytes, bytes):
            raise WazuhException(1105, "Type must be bytes")

        msg_length = len(msg_bytes)
        data = pack(header_format, msg_length) + msg_bytes if header_format else msg_bytes
        self.transport.write(data)

        if self.is_connection_lost():
            await self.close()
            raise WazuhException(1014, "Socket connection was closed")

        if msg_length == 0:
            raise WazuhException(1014, "Number of sent bytes is 0")
        return data

    async def receive(self, header_size=None):
        """Return the content of the socket.

        Parameters
        ----------
        header_size : int
            Size of the header to be extracted from the message received.

        Raises
        ------
        WazuhException(1014)
            If there is no connection with the socket.
        """
        try:
            await self.protocol.on_data_received
            return self.protocol.get_data()[header_size:] if header_size else self.protocol.get_data()
        except Exception as e:
            self.transport.close()
            raise WazuhException(1014, str(e))


class WazuhSocketJSON(WazuhAsyncSocket):
    """Handler class to connect and operate asynchronously with a socket using messages in JSON format."""
    def __init__(self):
        WazuhAsyncSocket.__init__(self)

    async def send(self, msg, header_format=None):
        """Converts the message from JSON format to bytes and send it to the socket. Returns that message.

        Parameters
        ----------
        msg : str
            The message in JSON format.
        header_format : str, optional
            Format of the header to be packed in the message.
        """
        return await WazuhAsyncSocket.send(self, dumps(msg).encode(), header_format)

    async def receive(self, header_size=None):
        """Get the data from the socket and converts it to JSON.

        Parameters
        ----------
        header_size : int
            Size of the header to be extracted from the message received.

        Raises
        ------
        WazuhException
            If the message obtained from the socket was an error message."""
        response = await WazuhAsyncSocket.receive(self, header_size)
        response = loads(response.decode())

        if 'error' in response.keys():
            if response['error'] != 0:
                raise WazuhException(response['error'], response['message'], cmd_error=True)
            else:
                return response['data']


daemons = {
    "authd": {"protocol": "TCP", "path": common.AUTHD_SOCKET, "header_format": "<I", "size": 4},
    "task-manager": {"protocol" : "TCP", "path": common.TASKS_SOCKET, "header_format": "<I", "size": 4},
    "wazuh-db": {"protocol": "TCP", "path": common.wdb_socket_path, "header_format": "<I", "size": 4}
}


async def wazuh_sendasync(daemon_name, message=None):
    """Send a message to the specified daemon's socket and wait for its response.

    Parameters
    ----------
    daemon_name : str
        Name of the daemon to send the message.
    message : str, optional
        Message in JSON format to be sent to the daemon's socket.
    """
    sock = WazuhSocketJSON()
    await sock.connect(daemons[daemon_name]['path'])
    await sock.send(message, daemons[daemon_name]['header_format'])
    data = await sock.receive(daemons[daemon_name]['size'])
    await sock.close()

    return data


async def wazuh_sendsync(daemon_name=None, message=None):
    """Send a message to the specified daemon's socket and wait for its response.

    Parameters
    ----------
    daemon_name : str
        Name of the daemon to send the message.
    message : str, optional
        Message in JSON format to be sent to the daemon's socket.
    """
    try:
        sock = OssecSocket(daemons[daemon_name]['path'])
        if isinstance(message, dict):
            message = dumps(message)
        sock.send(msg_bytes=message.encode(), header_format=daemons[daemon_name]['header_format'])
        data = sock.receive(header_format=daemons[daemon_name]['header_format'],
                            header_size=daemons[daemon_name]['size']).decode()
        sock.close()
    except WazuhException as e:
        raise e
    except Exception as e:
        raise WazuhInternalError(1014, extra_message=e)

    return data
