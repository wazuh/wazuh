# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
from wazuh.cluster.client import AbstractClient, AbstractClientManager
import uvloop


class LocalClientHandler(AbstractClient):

    def connection_made(self, transport):
        """
        Defines process of connecting to the server

        :param transport: socket to write data on
        """
        self.transport = transport


class LocalClient(AbstractClientManager):

    async def send_request_and_close(self, command, data):
        while self.client is None:
            await asyncio.sleep(0.5)
        result = await self.client.send_request(command, data)
        self.client.close()
        return result

    async def start(self):
        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        on_con_lost = loop.create_future()

        try:
            transport, protocol = await loop.create_unix_connection(
                                protocol_factory=lambda: LocalClientHandler(loop, on_con_lost, self.name,
                                                                            self.configuration['key'], self.logger),
                                path='{}/queue/cluster/c-internal.sock'.format('/var/ossec'))
        except ConnectionRefusedError:
            self.logger.error("Could not connect to server.")
            return
        except OSError as e:
            self.logger.error("Could not connect to server: {}.".format(e))
            return

        self.client = protocol

        try:
            await on_con_lost
        finally:
            transport.close()
