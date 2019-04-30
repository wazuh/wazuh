# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import itertools
import ssl
import uvloop
import time
from wazuh.cluster import common as c_common, cluster
from wazuh import common, exception, utils
import logging
from typing import Tuple, Dict
import random
import traceback


class AbstractServerHandler(c_common.Handler):
    """
    Defines abstract server protocol. Handles communication with a single client.
    """

    def __init__(self, server, loop, fernet_key, logger, cluster_items, tag="Client"):
        super().__init__(fernet_key=fernet_key, logger=logger, tag="{} {}".format(tag, random.randint(0, 1000)),
                         cluster_items=cluster_items)
        self.server = server
        self.loop = loop
        self.last_keepalive = time.time()
        self.tag = tag
        self.logger_filter.update_tag(self.tag)
        self.name = None
        self.ip = None
        self.transport = None

    def to_dict(self):
        return {'info': {'ip': self.ip, 'name': self.name}}

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
            self.name = ''
            raise exception.WazuhClusterError(3028, extra_message=data)
        elif self.name == self.server.configuration['node_name']:
            raise exception.WazuhClusterError(3029)
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
            if exc is None:
                self.logger.info("Disconnected.".format(self.name))
            else:
                self.logger.error(f"Error during connection with '{self.name}': {exc}.\n"
                                  f"{''.join(traceback.format_tb(exc.__traceback__))}")

            if self.name in self.server.clients:
                del self.server.clients[self.name]
        else:
            if exc is not None:
                self.logger.error(f"Error during handshake with incoming connection: {exc}", exc_info=True)
            else:
                self.logger.error("Error during handshake with incoming connection.")


class AbstractServer:
    """
    Defines an asynchronous server. Handles connections from all clients.
    """

    def __init__(self, performance_test: int, concurrency_test: int, configuration: Dict, cluster_items: Dict,
                 enable_ssl: bool, logger: logging.Logger, tag: str = "Abstract Server"):
        self.clients = {}
        self.performance = performance_test
        self.concurrency = concurrency_test
        self.configuration = configuration
        self.cluster_items = cluster_items
        self.enable_ssl = enable_ssl
        self.tag = tag
        self.logger = logger.getChild(tag)
        # logging tag
        self.logger.addFilter(cluster.ClusterFilter(tag=tag, subtag="Main"))
        self.tasks = [self.check_clients_keepalive]
        self.handler_class = AbstractServerHandler
        self.loop = asyncio.get_running_loop()

    def to_dict(self):
        return {'info': {'ip': self.configuration['nodes'][0], 'name': self.configuration['node_name']}}

    def setup_task_logger(self, task_tag: str):
        task_logger = self.logger.getChild(task_tag)
        task_logger.addFilter(cluster.ClusterFilter(tag=self.tag, subtag=task_tag))
        return task_logger

    def get_connected_nodes(self, filter_node=None, offset=0, limit=common.database_limit, sort=None, search=None,
                            select=None, filter_type='all') -> Dict:
        """
        Return all connected nodes, including the master node
        :return: A dictionary containing data from each node
        """
        def return_node(node_info):
            return (filter_node is None or node_info['name'] in filter_node) and (filter_type == 'all' or node_info['type'] == filter_type)

        default_fields = self.to_dict()['info'].keys()
        if select is None:
            select = default_fields
        else:
            if not set(select).issubset(default_fields):
                raise exception.WazuhError(code=1724, extra_message=', '.join(set(select) - default_fields),
                                           extra_remediation=', '.join(default_fields))

        if filter_type != 'all' and filter_type not in {'worker', 'master'}:
            raise exception.WazuhError(1728)

        if filter_node is not None:
            filter_node = set(filter_node) if isinstance(filter_node, list) else {filter_node}
            if not filter_node.issubset(set(itertools.chain(self.clients.keys(), [self.configuration['node_name']]))):
                raise exception.WazuhError(1730)

        res = [val.to_dict()['info'] for val in itertools.chain([self], self.clients.values())
               if return_node(val.to_dict()['info'])]

        if sort is not None:
            res = utils.sort_array(array=res, sort_by=sort['fields'], order=sort['order'],
                                   allowed_sort_fields=default_fields)
        if search is not None:
            res = utils.search_array(array=res, text=search['value'], negation=search['negation'])

        return {'totalItems': len(res), 'items': utils.cut_array([{k: v[k] for k in select} for v in res],
                                                                 offset, limit)}

    async def check_clients_keepalive(self):
        """
        Task to check the date of the last received keep alives from clients.
        """
        keep_alive_logger = self.setup_task_logger("Keep alive")
        while True:
            keep_alive_logger.debug("Calculating.")
            curr_timestamp = time.time()
            for client_name, client in self.clients.copy().items():
                if curr_timestamp - client.last_keepalive > self.cluster_items['intervals']['master']['max_allowed_time_without_keepalive']:
                    keep_alive_logger.error("No keep alives have been received from {} in the last minute. "
                                            "Disconnecting".format(client_name))
                    client.transport.close()
            keep_alive_logger.debug("Calculated.")
            await asyncio.sleep(self.cluster_items['intervals']['master']['check_worker_lastkeepalive'])

    async def echo(self):
        while True:
            for client_name, client in self.clients.items():
                self.logger.debug("Sending echo to worker {}".format(client_name))
                self.logger.info((await client.send_request(b'echo-m', b'keepalive ' + client_name)).decode())
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
        self.loop.set_exception_handler(c_common.asyncio_exception_handler)

        if self.enable_ssl:
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile='{}/etc/sslmanager.cert'.format(common.ossec_path),
                                        keyfile='{}/etc/sslmanager.key'.format(common.ossec_path))
        else:
            ssl_context = None

        try:
            server = await self.loop.create_server(
                    protocol_factory=lambda: self.handler_class(server=self, loop=self.loop, logger=self.logger,
                                                                fernet_key=self.configuration['key'],
                                                                cluster_items=self.cluster_items),
                    host=self.configuration['bind_addr'], port=self.configuration['port'], ssl=ssl_context)
        except OSError as e:
            self.logger.error("Could not start master: {}".format(e))
            raise KeyboardInterrupt

        self.logger.info('Serving on {}'.format(server.sockets[0].getsockname()))
        self.tasks.append(server.serve_forever)

        async with server:
            # use asyncio.gather to run both tasks in parallel
            await asyncio.gather(*map(lambda x: x(), self.tasks))
