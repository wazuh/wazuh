# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import uvloop
from typing import Tuple
import json
import random
from wazuh.cluster import server, common
from wazuh.cluster.dapi import dapi


class LocalServerHandler(server.AbstractServerHandler):

    def connection_made(self, transport):
        """
        Defines the process of accepting a connection

        :param transport: socket to write data on
        """
        self.name = str(random.SystemRandom().randint(0, 2 ** 32 - 1))
        self.transport = transport
        self.server.clients[self.name] = self
        self.tag = "Local Handler " + self.name
        self.logger_filter.update_tag(self.tag)
        self.logger.info('Connection received in local server. Client name: {}'.format(self.name))

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        if command == b'get_config':
            return self.get_config()
        elif command == b'get_nodes':
            return self.get_nodes(data)
        elif command == b'get_health':
            return self.get_health(data)
        elif command == b'dapi':
            self.server.dapi.add_request(self.name.encode() + b' ' + data)
            return b'ok', b'Added request to API requests queue'
        else:
            return super().process_request(command, data)

    def get_config(self) -> Tuple[bytes, bytes]:
        return b'ok', json.dumps(self.server.configuration).encode()

    def get_nodes(self, filter_nodes) -> Tuple[bytes, bytes]:
        return b'ok', json.dumps(self.server.node.get_connected_nodes(filter_nodes)).encode()

    def get_health(self, filter_nodes) -> Tuple[bytes, bytes]:
        return b'ok', json.dumps(self.server.node.get_health(filter_nodes)).encode()


class LocalServer(server.AbstractServer):

    def __init__(self, node: server.AbstractServer, **kwargs):
        super().__init__(**kwargs, tag="Local Server")
        self.node = node
        self.node.local_server = self
        self.dapi = dapi.APIRequestQueue(server=self)
        self.tasks.append(self.dapi.run)

    async def start(self):
        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(common.asyncio_exception_handler)

        try:
            server = await loop.create_unix_server(protocol_factory=lambda: LocalServerHandler(server=self, loop=loop,
                                                                                               fernet_key='',
                                                                                               logger=self.logger),
                                                   path='{}/queue/cluster/c-internal.sock'.format('/var/ossec'))
        except OSError as e:
            self.logger.error("Could not create server: {}".format(e))
            raise KeyboardInterrupt

        self.logger.info('Serving on {}'.format(server.sockets[0].getsockname()))

        self.tasks.append(server.serve_forever)

        async with server:
            # use asyncio.gather to run both tasks in parallel
            await asyncio.gather(*map(lambda x: x(), self.tasks))
