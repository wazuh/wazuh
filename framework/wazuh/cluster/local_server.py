# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import uvloop
from typing import Tuple, Union
import json
import random
from wazuh.cluster import server, common, client
from wazuh.cluster.dapi import dapi


class LocalServerHandler(server.AbstractServerHandler):

    def connection_made(self, transport):
        """
        Defines the process of accepting a connection

        :param transport: socket to write data on
        """
        self.name = str(random.SystemRandom().randint(0, 2 ** 20 - 1))
        self.transport = transport
        self.server.clients[self.name] = self
        self.tag = "Local " + self.name
        self.logger_filter.update_tag(self.tag)
        self.logger.info('Connection received in local server. Client name: {}'.format(self.name))

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        if command == b'get_config':
            return self.get_config()
        elif command == b'get_nodes':
            return self.get_nodes(data)
        elif command == b'get_health':
            return self.get_health(data)
        else:
            return super().process_request(command, data)

    def get_config(self) -> Tuple[bytes, bytes]:
        return b'ok', json.dumps(self.server.configuration).encode()

    def get_nodes(self, filter_nodes) -> Tuple[bytes, bytes]:
        return b'ok', json.dumps(self.server.node.get_connected_nodes(filter_nodes)).encode()

    def get_health(self, filter_nodes) -> Tuple[bytes, bytes]:
        return b'ok', json.dumps(self.server.node.get_health(filter_nodes)).encode()


class LocalServer(server.AbstractServer):

    def __init__(self, node: Union[server.AbstractServer, client.AbstractClientManager], **kwargs):
        super().__init__(**kwargs, tag="Local Server")
        self.node = node
        self.node.local_server = self
        self.handler_class = LocalServerHandler

    async def start(self):
        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(common.asyncio_exception_handler)

        try:
            server = await loop.create_unix_server(protocol_factory=lambda: self.handler_class(server=self, loop=loop,
                                                                                               fernet_key='',
                                                                                               logger=self.logger,
                                                                                               cluster_items=self.cluster_items),
                                                   path='{}/queue/cluster/c-internal.sock'.format('/var/ossec'))
        except OSError as e:
            self.logger.error("Could not create server: {}".format(e))
            raise KeyboardInterrupt

        self.logger.info('Serving on {}'.format(server.sockets[0].getsockname()))

        self.tasks.append(server.serve_forever)

        async with server:
            # use asyncio.gather to run both tasks in parallel
            await asyncio.gather(*map(lambda x: x(), self.tasks))


class LocalServerHandlerMaster(LocalServerHandler):

    def process_request(self, command: bytes, data: bytes):
        if command == b'dapi':
            self.server.dapi.add_request(self.name.encode() + b' ' + data)
            return b'ok', b'Added request to API requests queue'
        elif command == b'dapi_forward':
            node_name, request = data.split(b' ', 1)
            asyncio.create_task(self.server.node.clients[node_name.decode()].
                                send_request(b'dapi', self.name.encode() + b' ' + request))
            return b'ok', b'Request forwarded to worker node'
        else:
            return super().process_request(command, data)


class LocalServerMaster(LocalServer):

    def __init__(self, node: server.AbstractServer, **kwargs):
        super().__init__(node=node, **kwargs)
        self.handler_class = LocalServerHandlerMaster
        self.dapi = dapi.APIRequestQueue(server=self)
        self.tasks.append(self.dapi.run)


class LocalServerHandlerWorker(LocalServerHandler):

    def process_request(self, command: bytes, data: bytes):
        if command == b'dapi':
            asyncio.create_task(self.server.node.client.send_request(b'dapi', self.name.encode() + b' ' + data))
            return b'ok', b'Added request to API requests queue'
        else:
            return super().process_request(command, data)


class LocalServerWorker(LocalServer):

    def __init__(self, node: client.AbstractClientManager, **kwargs):
        super().__init__(node=node, **kwargs)
        self.handler_class = LocalServerHandlerWorker
