# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import itertools
import logging
import os
import random
import ssl
import time
import traceback
from typing import Tuple, Dict

import uvloop

from wazuh.core import common, exception, utils
from wazuh.core.cluster import common as c_common
from wazuh.core.cluster.utils import ClusterFilter, context_tag, context_subtag


class AbstractServerHandler(c_common.Handler):
    """
    Define abstract server protocol. Handle communication with a single client.
    """

    def __init__(self, server, loop: asyncio.AbstractEventLoop, fernet_key: str,
                 cluster_items: Dict, logger: logging.Logger = None, tag: str = "Client"):
        """Class constructor.

        Parameters
        ----------
        server : AbstractServer object
            Abstract server object that created this handler.
        loop : asyncio.AbstractEventLoop
            Asyncio loop.
        fernet_key : str
            Key used to encrypt and decrypt messages.
        cluster_items : dict
            Cluster.json object containing cluster internal variables.
        logger : Logger object
            Logger object to use.
        tag : str
            Log tag.
        """
        super().__init__(fernet_key=fernet_key, logger=logger, tag=f"{tag} {random.randint(0, 1000)}",
                         cluster_items=cluster_items)
        self.server = server
        self.loop = loop
        self.last_keepalive = time.time()
        self.tag = tag
        context_tag.set(self.tag)
        self.name = None
        self.ip = None
        self.transport = None

    def to_dict(self) -> Dict:
        """Get basic info from AbstractServerHandler instance.

        Returns
        -------
        dict
            Basic information (ip, name).
        """
        return {'info': {'ip': self.ip, 'name': self.name}}

    def connection_made(self, transport):
        """Define the process of accepting a connection.

        Parameters
        ----------
        transport : asyncio.Transport
            Socket to write data on.
        """
        peername = transport.get_extra_info('peername')
        self.logger.info(f'Connection from {peername}')
        self.ip = peername[0]
        self.transport = transport

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """Define commands for servers.

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
        if command == b"echo-c":
            return self.echo_master(data)
        elif command == b'hello':
            return self.hello(data)
        else:
            return super().process_request(command, data)

    def echo_master(self, data: bytes) -> Tuple[bytes, bytes]:
        """Update last_keepalive.

        Parameters
        ----------
        data : bytes
            Data to echo.

        Returns
        -------
        bytes
            Result.
        data : bytes
            Response message.
        """
        self.last_keepalive = time.time()
        return b'ok-m ', data

    def hello(self, data: bytes) -> Tuple[bytes, bytes]:
        """Add a client's data to global clients dictionary.

        Parameters
        ----------
        data : bytes
            Client's name.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        self.name = data.decode()
        if self.name in self.server.clients:
            self.name = ''
            raise exception.WazuhClusterError(3028, extra_message=data)
        elif self.name == self.server.configuration['node_name']:
            raise exception.WazuhClusterError(3029)
        else:
            self.server.clients[self.name] = self
            self.tag = f'{self.tag} {self.name}'
            context_tag.set(self.tag)
            return b'ok', f'Client {self.name} added'.encode()

    def process_response(self, command: bytes, payload: bytes) -> bytes:
        """Define response commands for servers.

        Parameters
        ----------
        command : bytes
            Response command received.
        payload : bytes
            Data received.

        Returns
        -------
        bytes
            Result message.
        """
        if command == b'ok-c':
            return b"Sucessful response from client: " + payload
        else:
            return super().process_response(command, payload)

    def connection_lost(self, exc):
        """Define process of closing connection with the server.

        Remove client from global clients dictionary and log the exception if any.

        Parameters
        ----------
        exc : Exception
            In case the connection was lost due to an exception, it will be contained in this variable.
        """
        if self.name:
            if exc is None:
                self.logger.debug("Disconnected.".format(self.name))
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
    Define an asynchronous server. Handle connections from all clients.
    """

    def __init__(self, performance_test: int, concurrency_test: int, configuration: Dict, cluster_items: Dict,
                 enable_ssl: bool, logger: logging.Logger = None, tag: str = "Abstract Server"):
        """Class constructor.

        Parameters
        ----------
        performance_test : int
            Message length to use in the performance test.
        concurrency_test : int
            Number of requests to do in the concurrency test.
        configuration : dict
            ossec.conf cluster configuration.
        cluster_items : dict
            cluster.json cluster internal configuration.
        enable_ssl : bool
            Whether to enable asyncio's SSL support.
        logger : Logger object
            Logger to use.
        tag : str
            Log tag.
        """
        self.clients = {}
        self.performance = performance_test
        self.concurrency = concurrency_test
        self.configuration = configuration
        self.cluster_items = cluster_items
        self.enable_ssl = enable_ssl
        self.tag = tag
        self.logger = logging.getLogger('wazuh') if not logger else logger
        # logging tag
        context_tag.set(self.tag)
        context_subtag.set("Main")
        self.tasks = [self.check_clients_keepalive]
        self.handler_class = AbstractServerHandler
        self.loop = asyncio.get_running_loop()

    def to_dict(self) -> Dict:
        """Get basic info from AbstractServer instance.

        Returns
        -------
        dict
            Basic information (ip, name).
        """
        return {'info': {'ip': self.configuration['nodes'][0], 'name': self.configuration['node_name']}}

    def setup_task_logger(self, task_tag: str) -> logging.Logger:
        """Create logger with a task_tag.

        Parameters
        ----------
        task_tag : str
            Tag describing the synchronization process.

        Returns
        -------
        task_logger : logging.Logger
            Logger created.
        """
        task_logger = self.logger.getChild(task_tag)
        task_logger.addFilter(ClusterFilter(tag=self.tag, subtag=task_tag))
        return task_logger

    def get_connected_nodes(self, filter_node: str = None, offset: int = 0, limit: int = common.database_limit,
                            sort: Dict = None, search: Dict = None, select: Dict = None,
                            filter_type: str = 'all') -> Dict:
        """Get all connected nodes, including the master node.

        Parameters
        ----------
        filter_node : str, list
            Node to return.
        offset : int
            First element to return.
        limit : int
            Maximum number of elements to return.
        sort : dict
            Sorts the collection by a field or fields.
        search : dict
            Looks for elements with the specified string.
        select : dict
            Select which fields to return (separated by comma).
        filter_type : str
            Type of node (worker/master).

        Returns
        -------
        dict
            Data from each node.
        """

        def return_node(node_info: Dict) -> bool:
            """Return whether the node must be added to the result or not.

            Parameters
            ----------
            node_info : dict
                Node information.

            Returns
            -------
            bool
                Whether the node must be added to the result or not.
            """
            return (filter_node is None or node_info['name'] in filter_node) and (
                        filter_type == 'all' or node_info['type'] == filter_type)

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
                raise exception.WazuhResourceNotFound(1730)

        res = [val.to_dict()['info'] for val in itertools.chain([self], self.clients.values())
               if return_node(val.to_dict()['info'])]

        return utils.process_array([{k: v[k] for k in select} for v in res],
                                   search_text=search['value'] if search is not None else None,
                                   complementary_search=search['negation'] if search is not None else False,
                                   sort_by=sort['fields'] if sort is not None else None,
                                   sort_ascending=False if sort is not None and sort['order'] == 'desc' else True,
                                   allowed_sort_fields=default_fields,
                                   offset=offset,
                                   limit=limit)

    async def check_clients_keepalive(self):
        """Check date of the last received keep alive.

        Task to check the date of the last received keep alive from clients. It is started when
        the server starts and it runs every self.cluster_items['intervals']['master']['check_worker_lastkeepalive']
        seconds.
        """
        keep_alive_logger = self.setup_task_logger("Keep alive")
        while True:
            keep_alive_logger.debug("Calculating.")
            curr_timestamp = time.time()
            # Iterate all clients and close the connection when their last keepalive is older than allowed.
            for client_name, client in self.clients.copy().items():
                if curr_timestamp - client.last_keepalive > self.cluster_items['intervals']['master']['max_allowed_time_without_keepalive']:
                    keep_alive_logger.error("No keep alives have been received from {} in the last minute. "
                                            "Disconnecting".format(client_name))
                    client.transport.close()
            keep_alive_logger.debug("Calculated.")
            await asyncio.sleep(self.cluster_items['intervals']['master']['check_worker_lastkeepalive'])

    async def echo(self):
        """Send an echo message to all clients every 3 seconds."""
        while True:
            for client_name, client in self.clients.items():
                self.logger.debug(f"Sending echo to worker {client_name}")
                self.logger.info((await client.send_request(b'echo-m', b'keepalive ' + client_name)).decode())
            await asyncio.sleep(3)

    async def performance_test(self):
        """Send a big message to all clients every 3 seconds."""
        while True:
            for client_name, client in self.clients.items():
                before = time.time()
                response = await client.send_request(b'echo', b'a' * self.performance)
                self.logger.info(f"Received size: {len(response)} // Time: {time.time() - before}")
            await asyncio.sleep(3)

    async def concurrency_test(self):
        """Send lots of messages in a row to all clients. Then rests for 10 seconds."""
        while True:
            before = time.time()
            for i in range(self.concurrency):
                for client_name, client in self.clients.items():
                    await client.send_request(b'echo', f'concurrency {i} client {client_name}'.encode())
            self.logger.info(f"Time sending {self.concurrency} messages: {time.time() - before}")
            await asyncio.sleep(10)

    async def start(self):
        """Start the server and the infinite asynchronous tasks."""
        # Get a reference to the event loop as we plan to use low-level APIs.
        context_tag.set(self.tag)
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop.set_exception_handler(c_common.asyncio_exception_handler)

        if self.enable_ssl:
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=os.path.join(common.ossec_path, 'etc', 'sslmanager.cert'),
                                        keyfile=os.path.join(common.ossec_path, 'etc', 'sslmanager.key'))
        else:
            ssl_context = None

        try:
            server = await self.loop.create_server(
                protocol_factory=lambda: self.handler_class(server=self, loop=self.loop, logger=self.logger,
                                                            fernet_key=self.configuration['key'],
                                                            cluster_items=self.cluster_items),
                host=self.configuration['bind_addr'], port=self.configuration['port'], ssl=ssl_context)
        except OSError as e:
            self.logger.error(f"Could not start master: {e}")
            raise KeyboardInterrupt

        self.logger.info(f'Serving on {server.sockets[0].getsockname()}')
        self.tasks.append(server.serve_forever)

        async with server:
            # Use asyncio.gather to run both tasks in parallel.
            await asyncio.gather(*map(lambda x: x(), self.tasks))
