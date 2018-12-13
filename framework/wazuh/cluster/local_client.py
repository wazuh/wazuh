# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import json
import logging
from wazuh.cluster import client, cluster
import uvloop
from wazuh import common


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
        if command == b'dapi_res':
            self.response = data
            self.response_available.set()
            return b'ok', b'Response received'
        else:
            return super().process_request(command, data)


class LocalClient(client.AbstractClientManager):

    def __init__(self, command: bytes, data: bytes):
        super().__init__(configuration=cluster.read_config(), enable_ssl=False, performance_test=0, concurrency_test=0,
                         file='', string=0, logger=logging.getLogger(), tag="Local Client",
                         cluster_items=cluster.get_cluster_items())
        self.request_result = None
        self.command = command
        self.data = data

    async def start(self):
        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        on_con_lost = loop.create_future()

        transport, protocol = await loop.create_unix_connection(
                            protocol_factory=lambda: LocalClientHandler(loop=loop, on_con_lost=on_con_lost,
                                                                        name=self.name, logger=self.logger,
                                                                        fernet_key='', cluster_items=self.cluster_items,
                                                                        manager=self),
                            path='{}/queue/cluster/c-internal.sock'.format(common.ossec_path))

        result = (await protocol.send_request(self.command, self.data)).decode()
        if result.startswith('Error'):
            request_result = json.dumps({'error': 1000, 'message': result})
        else:
            if self.command == b'dapi' or self.command == b'dapi_forward' or result == 'Sent request to master node':
                try:
                    await asyncio.wait_for(protocol.response_available.wait(),
                                           timeout=self.cluster_items['intervals']['communication']['timeout_api_request'])
                    request_result = protocol.response.decode()
                except asyncio.TimeoutError:
                    request_result = json.dumps({'error': 1000, 'message': 'Timeout exceeded'})
            else:
                request_result = result
        return request_result


async def execute(command: bytes, data: bytes):
    return await LocalClient(command, data).start()

