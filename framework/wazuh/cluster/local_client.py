# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import json
import logging
from wazuh.cluster import client, cluster
import uvloop


class LocalClientHandler(client.AbstractClient):

    def connection_made(self, transport):
        """
        Defines process of connecting to the server

        :param transport: socket to write data on
        """
        self.transport = transport


class LocalClient(client.AbstractClientManager):

    def __init__(self):
        super().__init__(configuration=cluster.read_config(), enable_ssl=False, performance_test=0, concurrency_test=0,
                         file='', string=0, logger=logging.getLogger(), tag="Local Client")
        self.request_result = None

    async def send_request(self, command, data):
        while self.client is None:
            await asyncio.sleep(0.5)
        result = await self.client.send_request(command, data)
        if result.startswith(b'Error'):
            self.request_result = {'error': 1000, 'message': result}
        else:
            self.request_result = json.loads(result)
        self.client.close()

    async def start(self):
        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        on_con_lost = loop.create_future()

        transport, protocol = await loop.create_unix_connection(
                            protocol_factory=lambda: LocalClientHandler(loop, on_con_lost, self.name,
                                                                        self.configuration['key'], self.logger),
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
