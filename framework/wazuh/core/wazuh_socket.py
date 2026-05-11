# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

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


daemons = {
    "authd": {"protocol": "TCP", "path": common.AUTHD_SOCKET, "header_format": "<I", "size": 4},
    "task-manager": {"protocol": "TCP", "path": common.TASKS_SOCKET, "header_format": "<I", "size": 4},
    "wazuh-manager-db": {"protocol": "TCP", "path": common.WDB_SOCKET, "header_format": "<I", "size": 4},
    "remoted": {"protocol": "TCP", "path": common.REMOTED_SOCKET, "header_format": "<I", "size": 4}
}


async def wazuh_sendsync(daemon_name: str = None, message: str = None) -> dict:
    """Send a message to the specified daemon's socket and wait for its response.

    Parameters
    ----------
    daemon_name : str
        Name of the daemon to send the message.
    message : str, optional
        Message in JSON format to be sent to the daemon's socket.

    Raises
    ------
    WazuhInternalError(1014)
        Error communicating with socket.

    Returns
    -------
    dict
        Data received.
    """
    try:
        sock = WazuhSocket(daemons[daemon_name]['path'])
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


def create_wazuh_socket_message(origin=None, command=None, parameters=None):
    communication_protocol_message = {'version': SOCKET_COMMUNICATION_PROTOCOL_VERSION}

    if origin:
        communication_protocol_message['origin'] = origin

    if command:
        communication_protocol_message['command'] = command

    if parameters:
        communication_protocol_message['parameters'] = parameters

    return communication_protocol_message
