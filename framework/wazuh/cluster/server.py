# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import json
import ssl
import uvloop
import time
from wazuh.cluster import common, cluster
import logging
from typing import Tuple, Dict
import random


class AbstractServerHandler(common.Handler):
    """
    Defines abstract server protocol. Handles communication with a single client.
    """

    def __init__(self, server, loop, fernet_key, logger, tag="Client"):
        super().__init__(fernet_key=fernet_key, logger=logger, tag="{} {}".format(tag, random.randint(0, 1000)))
        self.server = server
        self.loop = loop
        self.last_keepalive = time.time()
        self.tag = tag
        self.logger_filter.update_tag(self.tag)
        self.name = None
        self.ip = None
        self.transport = None

    def __dict__(self):
        return {'info': {'address': self.ip, 'name': self.name}}

    def connection_made(self, transport):
        """
        Defines the process of accepting a connection

        :param transport: socket to write data on
        """
        peername = transport.get_extra_info('peername')
        self.logger.info('Connection from {}'.format(peername))
        self.ip = peername[0]
        self.transport = transport

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines commands for servers

        :param command: Received command from client.
        :param data: Received data from client.
        :return: message to send
        """
        if command == b"echo-c":
            return self.echo_master(data)
        elif command == b'hello':
            return self.hello(data)
        else:
            return super().process_request(command, data)

    def echo_master(self, data: bytes) -> Tuple[bytes, bytes]:
        self.last_keepalive = time.time()
        return b'ok-m ', data

    def hello(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Adds a client's data to global clients dictionary

        :param data: client's data -> name
        :return: successful result
        """
        self.name = data.decode()
        if self.name in self.server.clients:
            self.logger.error("Client {} already present".format(data))
            return b'err', b'Client already present'
        elif self.name == self.server.configuration['node_name']:
            self.logger.error("Connected client with same name as the master: {}".format(self.name))
            return b'err', b'Same name as master'
        else:
            self.server.clients[self.name] = self
            self.tag = '{} {}'.format(self.tag, self.name)
            self.logger_filter.update_tag(self.tag)
            return b'ok', 'Client {} added'.format(self.name).encode()

    def process_response(self, command: bytes, payload: bytes) -> bytes:
        """
        Defines response commands for servers

        :param command: response command received
        :param payload: data received
        :return:
        """
        if command == b'ok-c':
            return b"Sucessful response from client: " + payload
        else:
            return super().process_response(command, payload)

    def connection_lost(self, exc):
        """
        Defines process of closing connection with the server

        :param exc:
        :return:
        """
        if self.name:
            self.logger.info("The client '{}' closed the connection".format(self.name))
            del self.server.clients[self.name]
        else:
            self.logger.error("Error during handshake with incoming client: {}".format(exc))


class AbstractServer:
    """
    Defines an asynchronous server. Handles connections from all clients.
    """

    def __init__(self, performance_test, concurrency_test, configuration: Dict, enable_ssl: bool,
                 logger: logging.Logger, tag: str = "Abstract Server"):
        self.clients = {}
        self.performance = performance_test
        self.concurrency = concurrency_test
        self.configuration = configuration
        self.enable_ssl = enable_ssl
        self.logger = logger.getChild(tag)
        # logging tag
        self.logger.addFilter(cluster.ClusterFilter(tag=tag))
        self.tasks = [self.check_clients_keepalive]
        self.handler_class = AbstractServerHandler

    def __dict__(self):
        return {'info': {'address': self.configuration['nodes'][0], 'name': self.configuration['node_name']}}

    def get_connected_nodes(self, filter_nodes) -> Dict:
        """
        Return all connected nodes, including the master node
        :return: A dictionary containing data from each node
        """
        filter_nodes = json.loads(filter_nodes)
        nodes = {self.configuration['node_name']: self.__dict__()['info']} if filter_nodes is None or self.configuration['node_name'] in filter_nodes else {}
        return {**nodes, **{key: val.__dict__()['info'] for key, val in self.clients.items() if filter_nodes is None or key in filter_nodes}}

    async def check_clients_keepalive(self):
        """
        Task to check the date of the last received keep alives from clients.
        """
        while True:
            curr_timestamp = time.time()
            for client_name, client in self.clients.items():
                if curr_timestamp - client.last_keepalive > 30:
                    self.logger.error("No keep alives have been received from {} in the last minute. Disconnecting".format(
                        client_name))
                    client.transport.close()
            await asyncio.sleep(30)

    async def echo(self):
        while True:
            for client_name, client in self.clients.items():
                self.logger.debug("Sending echo to client {}".format(client_name))
                self.logger.info(await client.send_request(b'echo-m', b'keepalive ' + client_name))
            await asyncio.sleep(3)

    async def performance_test(self):
        while True:
            for client_name, client in self.clients.items():
                before = time.time()
                response = await client.send_request(b'echo', b'a' * self.performance)
                after = time.time()
                self.logger.info("Received size: {} // Time: {}".format(len(response), after - before))
            await asyncio.sleep(3)

    async def concurrency_test(self):
        while True:
            before = time.time()
            for i in range(self.concurrency):
                for client_name, client in self.clients.items():
                    response = await client.send_request(b'echo',
                                                         'concurrency {} client {}'.format(i, client_name).encode())
            after = time.time()
            self.logger.info("Time sending {} messages: {}".format(self.concurrency, after - before))
            await asyncio.sleep(10)

    async def start(self):
        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(common.asyncio_exception_handler)

        if self.enable_ssl:
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile='{}/etc/sslmanager.cert'.format('/var/ossec'),
                                        keyfile='{}/etc/sslmanager.key'.format('/var/ossec'))
        else:
            ssl_context = None

        try:
            server = await loop.create_server(
                    protocol_factory=lambda: self.handler_class(server=self, loop=loop, logger=self.logger,
                                                                fernet_key=self.configuration['key']),
                    host=self.configuration['bind_addr'], port=self.configuration['port'], ssl=ssl_context)
        except OSError as e:
            self.logger.error("Could not create server: {}".format(e))
            raise KeyboardInterrupt

        self.logger.info('Serving on {}'.format(server.sockets[0].getsockname()))
        self.tasks.append(server.serve_forever)

        async with server:
            # use asyncio.gather to run both tasks in parallel
            await asyncio.gather(*map(lambda x: x(), self.tasks))
