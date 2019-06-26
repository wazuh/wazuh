# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import json
import logging
from typing import Tuple

from wazuh.cluster import client, cluster
import uvloop
from wazuh import common, exception


class LocalClientHandler(client.AbstractClient):
    """
    Handles connection with the cluster's local server.
    """
    def __init__(self, **kwargs):
        """
        Class constructor
        :param kwargs: Arguments for parent constructor class
        """
        super().__init__(**kwargs)
        self.response_available = asyncio.Event()
        self.response = b''

    def connection_made(self, transport):
        """
        Defines process of connecting to the server. A hello is not necessary because the local server generates a
        random name for the local client.

        :param transport: socket to write data on
        """
        self.transport = transport

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines commands available in a local client
        :param command: Received command
        :param data: Received payload
        :return: A response
        """
        self.logger.debug("Command received: {}".format(command))
        if command == b'dapi_res' or command == b'send_f_res':
            if data.startswith(b'Error'):
                return b'err', self.process_error_from_peer(data)
            elif data not in self.in_str:
                return b'err', self.process_error_from_peer(b'Error receiving string: ID ' + data + b' not found.')
            self.response = self.in_str[data].payload
            self.response_available.set()
            return b'ok', b'Distributed api response received'
        elif command == b'control_res':
            if data.startswith(b'Error'):
                return b'err', self.process_error_from_peer(data)
            self.response = data
            self.response_available.set()
            return b'ok', b'Response received'
        elif command == b'dapi_err' or command == b'err':
            self.response = json.dumps({'error': 3009, 'message': data.decode()}).encode()
            self.response_available.set()
            return b'ok', b'Response received'
        else:
            return super().process_request(command, data)

    def process_error_from_peer(self, data: bytes):
        """
        Handles "err" response.
        :param data: Error message
        :return: Confirmation message
        """
        if data.startswith(b'WazuhException'):
            type_error, code, message = data.split(b' ', 2)
            self.response = json.dumps({'error': int(code), 'message': message.decode()}).encode()
            self.response_available.set()
            extra_msg = b'' if b': ' not in message else message.split(b':', 1)[1]
            return type_error + b' ' + code + b' ' + extra_msg
        else:
            self.response = json.dumps({'error': 3009, 'message': data.decode()}).encode()
            self.response_available.set()
            return b"Error processing request: " + data


class LocalClient(client.AbstractClientManager):
    """
    Initializes variables, connects to the server, sends a request, waits for a response and disconnects.
    """
    def __init__(self, command: bytes, data: bytes, wait_for_complete: bool):
        """
        Class constructor
        :param command: Command to send
        :param data: Payload to send
        :param wait_for_complete: Whether to enable timeout or not
        """
        super().__init__(configuration=cluster.read_config(), enable_ssl=False, performance_test=0, concurrency_test=0,
                         file='', string=0, logger=logging.getLogger(), tag="Local Client",
                         cluster_items=cluster.get_cluster_items())
        self.request_result = None
        self.command = command
        self.data = data
        self.wait_for_complete = wait_for_complete
        self.protocol = None
        self.transport = None

    async def start(self):
        """
        Connects to the server
        """
        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        on_con_lost = loop.create_future()

        try:
            self.transport, self.protocol = await loop.create_unix_connection(
                                             protocol_factory=lambda: LocalClientHandler(loop=loop, on_con_lost=on_con_lost,
                                                                                         name=self.name, logger=self.logger,
                                                                                         fernet_key='', manager=self,
                                                                                         cluster_items=self.cluster_items),
                                             path='{}/queue/cluster/c-internal.sock'.format(common.ossec_path))
        except ConnectionRefusedError:
            raise exception.WazuhException(3012)
        except Exception as e:
            raise exception.WazuhException(3009, str(e))

    async def send_api_request(self) -> str:
        """
        Sends a command to the server and waits for the response
        :return: Response from the server
        """
        result = (await self.protocol.send_request(self.command, self.data)).decode()
        if result.startswith('Error'):
            raise exception.WazuhException(3009, result)
        elif result.startswith('WazuhException'):
            _, code, message = result.split(' ', 2)
            raise exception.WazuhException(int(code), message)
        elif result == 'There are no connected worker nodes':
            request_result = '{}'
        else:
            if self.command == b'dapi' or self.command == b'dapi_forward' or self.command == b'send_file' or \
                    result == 'Sent request to master node':
                try:
                    timeout = None if self.wait_for_complete \
                        else self.cluster_items['intervals']['communication']['timeout_api_request']
                    await asyncio.wait_for(self.protocol.response_available.wait(), timeout=timeout)
                    request_result = self.protocol.response.decode()
                except asyncio.TimeoutError:
                    raise exception.WazuhException(3020)
            else:
                request_result = result
        return request_result


async def execute(command: bytes, data: bytes, wait_for_complete: bool) -> str:
    """
    Executes a command in the local client.
    :param command: Command to execute
    :param data: Payload
    :param wait_for_complete: Whether to enable timeout waiting for the response or not
    :return: The response encoded in a str
    """
    lc = LocalClient(command, data, wait_for_complete)
    await lc.start()
    return await lc.send_api_request()


async def send_file(path: str, node_name: str = None) -> bytes:
    """
    Sends a file to the local server
    :param path: Pathname
    :param node_name: Node to send the file to
    :return: The response encoded in bytes
    """
    lc = LocalClient(b'send_file', "{} {}".format(path, node_name).encode(), False)
    await lc.start()
    return (await lc.send_api_request()).encode()
