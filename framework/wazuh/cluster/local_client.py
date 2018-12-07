# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import json
import logging
from wazuh.cluster import client, cluster
import uvloop


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

    def __init__(self):
        super().__init__(configuration=cluster.read_config(), enable_ssl=False, performance_test=0, concurrency_test=0,
                         file='', string=0, logger=logging.getLogger(), tag="Local Client")
        self.request_result = None

    async def send_request(self, command, data):
        while self.client is None:
            await asyncio.sleep(0.5)
        result = (await self.client.send_request(command, data)).decode()
        if result.startswith('Error'):
            self.request_result = json.dumps({'error': 1000, 'message': result})
        else:
            if command == b'dapi':
                await self.client.response_available.wait()
                self.request_result = self.client.response.decode()
            else:
                self.request_result = result
        self.client.close()

    async def start(self):
        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        on_con_lost = loop.create_future()

        transport, protocol = await loop.create_unix_connection(
                            protocol_factory=lambda: LocalClientHandler(loop=loop, on_con_lost=on_con_lost,
                                                                        name=self.name, logger=self.logger,
                                                                        fernet_key='',
                                                                        manager=self),
                            path='{}/queue/cluster/c-internal.sock'.format('/var/ossec'))

        self.client = protocol

        try:
            await on_con_lost
        finally:
            transport.close()


async def execute(command: bytes, data: bytes):
    my_client = LocalClient()
    try:
        await asyncio.gather(my_client.start(), my_client.send_request(command=command, data=data))
    except asyncio.CancelledError:
        pass
    return my_client.request_result
