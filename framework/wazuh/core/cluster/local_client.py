# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import logging
from typing import Tuple
import os

import uvloop

import wazuh.core.cluster.utils
from wazuh.core import common, exception
from wazuh.core.cluster import client


class LocalClientHandler(client.AbstractClient):
    """
    Handle connection with the cluster's local server.
    """

    def __init__(self, **kwargs):
        """Class constructor.

        Parameters
        ----------
        kwargs
            Arguments for the parent class constructor.
        """
        super().__init__(**kwargs)
        self.response_available = asyncio.Event()
        self.response = b''

    def connection_made(self, transport):
        """Define process of connecting to the server.

        A 'hello' command is not necessary because the local server generates a
        random name for the local client.

        Parameters
        ----------
        transport : asyncio.Transport
            Socket to write data on.
        """
        self.transport = transport

    def _cancel_all_tasks(self):
        pass

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """Define commands available in a local client.

        Parameters
        ----------
        command : bytes
            Received command from client.
        data : bytes
            Received payload from client.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        self.logger.debug(f"Command received: {command}")
        if command == b'dapi_res' or command == b'send_f_res':
            if data.startswith(b'Error'):
                return b'err', self.process_error_from_peer(data)
            elif data not in self.in_str:
                return b'err', self.process_error_from_peer(b'Error receiving string: ID ' + data + b' not found.')
            self.response = self.in_str[data].payload
            self.response_available.set()
            return b'ok', b'Distributed api response received'
        elif command == b'ok':
            if data.startswith(b'Error'):
                return b'err', self.process_error_from_peer(data)
            self.response = data
            self.response_available.set()
            return b'ok', b'Sendsync response received'
        elif command == b'control_res':
            if data.startswith(b'Error'):
                return b'err', self.process_error_from_peer(data)
            self.response = data
            self.response_available.set()
            return b'ok', b'Response received'
        elif command == b'dapi_err':
            self.response = data
            self.response_available.set()
            return b'ok', b'Response received'
        elif command == b'err':
            self.response = data
            self.response_available.set()
            return b'ok', b'Error response received'
        else:
            return super().process_request(command, data)

    def process_error_from_peer(self, data: bytes):
        """Handle "err" response.

        Errors from the cluster come already formatted into JSON format, they can therefore be returned the same way.

        Parameters
        ----------
        data : bytes
            Error message.

        Returns
        -------
        data : bytes
            Error message in JSON format.
        """
        self.response = data
        self.response_available.set()
        return data

    def connection_lost(self, exc):
        """Mark the Future as done."""
        self.on_con_lost.set_result(True)


class LocalClient(client.AbstractClientManager):
    """
    Initialize variables, connect to the server, send a request, wait for a response and disconnect.
    """

    def __init__(self):
        """Class constructor"""
        super().__init__(configuration=wazuh.core.cluster.utils.read_config(), enable_ssl=False, performance_test=0,
                         concurrency_test=0, file='', string=0, logger=logging.getLogger(), tag="Local Client",
                         cluster_items=wazuh.core.cluster.utils.get_cluster_items())
        self.request_result = None
        self.protocol = None
        self.transport = None

    async def start(self):
        """Connect to the server and the necessary asynchronous tasks."""
        # Get a reference to the event loop as we plan to use low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        on_con_lost = loop.create_future()
        try:
            self.transport, self.protocol = await loop.create_unix_connection(
                                             protocol_factory=lambda: LocalClientHandler(loop=loop, on_con_lost=on_con_lost,
                                                                                         name=self.name, logger=self.logger,
                                                                                         fernet_key='', manager=self,
                                                                                         cluster_items=self.cluster_items),
                                             path=os.path.join(common.ossec_path, 'queue', 'cluster', 'c-internal.sock'))
        except (ConnectionRefusedError, FileNotFoundError):
            raise exception.WazuhInternalError(3012)
        except MemoryError:
            raise exception.WazuhInternalError(1119)
        except Exception as e:
            raise exception.WazuhInternalError(3009, str(e))

    async def send_api_request(self, command: bytes, data: bytes, wait_for_complete: bool) -> str:
        """Send DAPI request to the server and wait for response.

        Parameters
        ----------
        command : bytes
            Command to execute.
        data : bytes
            Data to send.
        wait_for_complete : bool
            Whether to raise a timeout exception or not.

        Returns
        -------
        request_result : dict
            API response.
        """
        result = (await self.protocol.send_request(command, data)).decode()
        if result == 'There are no connected worker nodes':
            request_result = {}
        else:
            # Wait for expected data if it is not returned by send_request(),
            # which occurs when the following commands are used.
            if command == b'dapi' or command == b'dapi_forward' or command == b'send_file' or command == b'sendasync' \
                    or result == 'Sent request to master node':
                try:
                    timeout = None if wait_for_complete \
                        else self.cluster_items['intervals']['communication']['timeout_api_request']
                    await asyncio.wait_for(self.protocol.response_available.wait(), timeout=timeout)
                    request_result = self.protocol.response.decode()
                except asyncio.TimeoutError:
                    raise exception.WazuhInternalError(3020)
            # If no data is expected (only the send_request() result), immediately return the output of send_request.
            else:
                request_result = result
        return request_result

    async def execute(self, command: bytes, data: bytes, wait_for_complete: bool) -> str:
        """Execute a command in the local client.

        Manage the connection with the local_server by creating such connection. Then, after sending a request
        and receiving the response, the connection is closed.

        Parameters
        ----------
        command : bytes
            Command to execute.
        data : bytes
            Data to send.
        wait_for_complete : bool
            Whether to raise a timeout exception or not.

        Returns
        -------
        result : str
            Request response.
        """
        await self.start()
        result = await self.send_api_request(command, data, wait_for_complete)
        self.transport.close()
        await self.protocol.on_con_lost
        return result

    async def send_file(self, path: str, node_name: str = None) -> str:
        """Send a file to the local server.

        Parameters
        ----------
        path : str
            Full path to file.
        node_name : str
            Name of the destination node.

        Returns
        -------
        str
            Request response.
        """
        await self.start()
        return await self.send_api_request(b'send_file', f"{path} {node_name}".encode(), False)
