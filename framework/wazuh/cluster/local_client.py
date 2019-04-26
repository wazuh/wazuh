# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import json
import logging
from typing import Dict

from wazuh.cluster import client, cluster
from wazuh.cluster.common import WazuhJSONEncoder
import uvloop
from wazuh import common, exception


class LocalClientHandler(client.AbstractClient):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.response_available = asyncio.Event()
        self.response = b''

    def connection_made(self, transport):
        """
        Defines process of connecting to the server

        :param transport: socket to write data on
        """
        self.transport = transport

    def process_request(self, command: bytes, data: bytes):
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
        elif command == b'dapi_err':
            self.response = data
            self.response_available.set()
            return b'ok', b'Response received'
        else:
            return super().process_request(command, data)

    def process_error_from_peer(self, data: bytes):
        """
        Errors from the cluster come already formatted into JSON format. Therefore they must be returned the same
        """
        self.response = data
        self.response_available.set()
        return data


class LocalClient(client.AbstractClientManager):

    def __init__(self, command: bytes, data: bytes, wait_for_complete: bool):
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

    async def send_api_request(self):
        result = (await self.protocol.send_request(self.command, self.data)).decode()
        if result == 'There are no connected worker nodes':
            request_result = {}
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


async def execute(command: bytes, data: bytes, wait_for_complete: bool) -> Dict:
    lc = LocalClient(command, data, wait_for_complete)
    await lc.start()
    return await lc.send_api_request()


async def send_file(path: str, node_name: str = None) -> Dict:
    lc = LocalClient(b'send_file', "{} {}".format(path, node_name).encode(), False)
    await lc.start()
    return await lc.send_api_request()
