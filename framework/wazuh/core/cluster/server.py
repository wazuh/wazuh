# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import contextlib
import functools
import inspect
import itertools
import logging
import ssl
import traceback
from time import perf_counter
from typing import Dict, Tuple
from uuid import uuid4

import uvloop
from wazuh.core import common, exception, utils
from wazuh.core.cluster import common as c_common
from wazuh.core.cluster.utils import ClusterFilter, context_tag
from wazuh.core.config.models.server import ServerConfig


class AbstractServerHandler(c_common.Handler):
    """Define abstract server protocol. Handle communication with a single client."""

    def __init__(
        self,
        server,
        loop: asyncio.AbstractEventLoop,
        server_config: ServerConfig,
        logger: logging.Logger = None,
        tag: str = 'Client',
    ):
        """Class constructor.

        Parameters
        ----------
        server : AbstractServer object
            Abstract server object that created this handler.
        loop : asyncio.AbstractEventLoop
            Asyncio loop.
        server_config : ServerConfig
            Object containing server configuration variables.
        logger : Logger object
            Logger object to use.
        tag : str
            Log tag.
        """
        super().__init__(logger=logger, tag=f'{tag} {str(uuid4().hex[:8])}', server_config=server_config)
        self.server = server
        self.loop = loop
        self.last_keepalive = utils.get_utc_now().timestamp()
        self.tag = tag
        context_tag.set(self.tag)
        self.name = None
        self.ip = None
        self.transport = None
        self.handler_tasks = []
        self.broadcast_queue = asyncio.Queue()

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
        if command == b'echo-c':
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
        self.last_keepalive = utils.get_utc_now().timestamp()
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
            raise exception.WazuhClusterError(3028, extra_message=data.decode())
        elif self.name == self.server_config.node.name:
            raise exception.WazuhClusterError(3029)
        else:
            self.server.clients[self.name] = self
            self.tag = f'{self.tag} {self.name}'
            context_tag.set(self.tag)
            self.handler_tasks.append(self.loop.create_task(self.broadcast_reader()))
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
            return b'Successful response from client: ' + payload
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
                self.logger.debug(f'Disconnected {self.name}.')
            else:
                self.logger.error(
                    f"Error during connection with '{self.name}': {exc}.\n"
                    f'{"".join(traceback.format_tb(exc.__traceback__))}',
                    exc_info=False,
                )
            if self.name in self.server.clients:
                del self.server.clients[self.name]
            for task in self.handler_tasks:
                task.cancel()
        elif exc is not None:
            self.logger.error(
                f'Error during handshake with incoming connection: {exc}. \n'
                f'{"".join(traceback.format_tb(exc.__traceback__))}',
                exc_info=False,
            )
        else:
            self.logger.error('Error during handshake with incoming connection.', exc_info=False)

    def add_request(self, broadcast_id, f, *args, **kwargs):
        """Add a request to the queue to execute a function in this server handler.

        Parameters
        ----------
        broadcast_id : Str or None
            Request identifier to be included in the queue.
        f : callable
            Function reference to be run. The function should be defined in this or in any inheriting class.
        *args
            Arguments to be passed to function `f`.
        **kwargs
            Keyword arguments to be passed to function `f`.
        """
        self.broadcast_queue.put_nowait(
            {'broadcast_id': broadcast_id, 'func': functools.partial(f, self, *args, **kwargs)}
        )

    async def broadcast_reader(self):
        """Execute functions added to the broadcast_queue of this server handler.

        Wait until something with this structure is added to the queue:
        {'broadcast_id': Union[Str, None], 'func': Callable}.

        The function 'func' is executed and its result is stored in a dict
        under the key 'broadcast_id', if it exists.
        """
        while True:
            q_item = await self.broadcast_queue.get()

            try:
                if inspect.iscoroutinefunction(q_item['func']):
                    result = await q_item['func']()
                else:
                    result = q_item['func']()
            except Exception as e:
                self.logger.error(f'Error while broadcasting function. ID: {q_item["broadcast_id"]}. Error: {e}.')
                result = e

            with contextlib.suppress(KeyError):
                self.server.broadcast_results[q_item['broadcast_id']][self.name] = result


class AbstractServer:
    """Define an asynchronous server. Handle connections from all clients."""

    NO_RESULT = 'no_result'

    def __init__(
        self,
        performance_test: int,
        concurrency_test: int,
        server_config: ServerConfig,
        logger: logging.Logger = None,
        tag: str = 'Abstract Server',
    ):
        """Class constructor.

        Parameters
        ----------
        performance_test : int
            Message length to use in the performance test.
        concurrency_test : int
            Number of requests to do in the concurrency test.
        server_config : ServerConfig
            Server configuration.
        logger : Logger object
            Logger to use.
        tag : str
            Log tag.
        """
        self.clients = {}
        self.performance = performance_test
        self.concurrency = concurrency_test
        self.server_config = server_config
        self.tag = tag
        self.logger = logging.getLogger('wazuh') if not logger else logger
        # logging tag
        context_tag.set(self.tag)
        self.tasks = [self.check_clients_keepalive]
        self.handler_class = AbstractServerHandler
        self.loop = asyncio.get_running_loop()
        self.broadcast_results = {}

    def broadcast(self, f, *args, **kwargs):
        """Add a function to the broadcast_queue of each server handler.

        Parameters
        ----------
        f : Callable
            Function to be run in each server handler.
        *args
            Arguments to be passed to function `f`.
        **kwargs
            Keyword arguments to be passed to function `f`.

        Notes
        -----
        This method does not allow determining whether the function has been
        executed in all server handlers or the result for each one. For those
        features, see `broadcast_add` and `broadcast_pop`.
        """
        for name, client in self.clients.items():
            try:
                client.add_request(None, f, *args, **kwargs)
                self.logger.debug2(f'Added broadcast request to execute "{f.__name__}" in {name}.')
            except Exception as e:
                self.logger.error(f'Error while adding broadcast request in {name}: {e}', exc_info=False)

    def broadcast_add(self, f, *args, **kwargs):
        """Add a function to the broadcast_queue of each server handler and obtain an identifier.

        Parameters
        ----------
        f : Callable
            Function to be run in each server handler.
        *args
            Arguments to be passed to function `f`.
        **kwargs
            Keyword arguments to be passed to function `f`.

        Returns
        -------
        broadcast_id : str
            Identifier to check the status of the broadcast request.

        Notes
        -----
        It is important to run `broadcast_pop` to remove the result entry from the
        broadcast_results dict after using this method. Otherwise, it will be kept
        until restarting the server. See `broadcast` method if broadcast results
        are not needed.
        """
        if self.clients:
            broadcast_id = str(uuid4())
            self.broadcast_results[broadcast_id] = {}

            for name, client in self.clients.items():
                try:
                    self.broadcast_results[broadcast_id][name] = AbstractServer.NO_RESULT
                    client.add_request(broadcast_id, f, *args, **kwargs)
                    self.logger.debug2(f'Added broadcast request to execute "{f.__name__}" in {name}.')
                except Exception as e:
                    self.broadcast_results[broadcast_id].pop(name, None)
                    self.logger.error(f'Error while adding broadcast request in {name}: {e}', exc_info=False)

            if not self.broadcast_results[broadcast_id]:
                self.broadcast_results.pop(broadcast_id, None)
            else:
                return broadcast_id

    def broadcast_pop(self, broadcast_id):
        """Get the broadcast result of all server handlers, if ready.

        Return False if `broadcast_id` exists but the requested function was not
        executed in all the server handlers. Otherwise, return a dictionary
        with the execution result in each server handler or True if the `broadcast_id`
        is unknown.

        If the dict is returned, said entry is removed from the broadcast_results dict.

        Parameters
        ----------
        broadcast_id : str
            Identifier to check the status of the broadcast request.

        Returns
        -------
        Dict, bool
            False if the `broadcast_id` exists but the request was not executed in all server handlers.
            True if the `broadcast_id` is unknown. Dict with results if the `broadcast_id` exists and
            the results are ready, it is, the request was executed in all server handlers.
        """
        for name, result in self.broadcast_results.get(broadcast_id, {}).items():
            if name in self.clients and result == AbstractServer.NO_RESULT:
                return False

        return self.broadcast_results.pop(broadcast_id, True)

    def to_dict(self) -> Dict:
        """Get basic info from AbstractServer instance.

        Returns
        -------
        dict
            Basic information (ip, name).
        """
        return {'info': {'ip': self.server_config.nodes[0], 'name': self.server_config.node.name}}

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

    def get_connected_nodes(
        self,
        filter_node: str = None,
        offset: int = 0,
        limit: int = common.DATABASE_LIMIT,
        sort: Dict = None,
        search: Dict = None,
        select: Dict = None,
        filter_type: str = 'all',
        distinct: bool = False,
    ) -> Dict:
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
        distinct : bool
            Look for distinct values.

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
                filter_type == 'all' or node_info['type'] == filter_type
            )

        default_fields = self.to_dict()['info'].keys()
        if select is None:
            select = default_fields
        else:
            if not set(select).issubset(default_fields):
                raise exception.WazuhError(
                    1724,
                    extra_message=', '.join(set(select) - default_fields),
                    extra_remediation=', '.join(default_fields),
                )

        if filter_type != 'all' and filter_type not in {'worker', 'master'}:
            raise exception.WazuhError(1728)

        if filter_node is not None:
            filter_node = set(filter_node) if isinstance(filter_node, list) else {filter_node}
            if not filter_node.issubset(set(itertools.chain(self.clients.keys(), [self.server_config.node.name]))):
                raise exception.WazuhResourceNotFound(1730)

        res = [
            val.to_dict()['info']
            for val in itertools.chain([self], self.clients.values())
            if return_node(val.to_dict()['info'])
        ]

        return utils.process_array(
            [{k: v[k] for k in select} for v in res],
            search_text=search['value'] if search is not None else None,
            complementary_search=search['negation'] if search is not None else False,
            sort_by=sort['fields'] if sort is not None else None,
            sort_ascending=False if sort is not None and sort['order'] == 'desc' else True,
            allowed_sort_fields=default_fields,
            offset=offset,
            limit=limit,
            distinct=distinct,
        )

    async def check_clients_keepalive(self):
        """Check date of the last received keep alive.

        Task to check the date of the last received keep alive from clients. It is started when
        the server starts and it runs every check_worker_lastkeepalive defined in the configuration
        seconds.
        """
        keep_alive_logger = self.setup_task_logger('Keep alive')
        while True:
            keep_alive_logger.debug('Calculating.')
            curr_timestamp = utils.get_utc_now().timestamp()
            # Iterate all clients and close the connection when their last keepalive is older than allowed.
            for client_name, client in self.clients.copy().items():
                if (
                    curr_timestamp - client.last_keepalive
                    > self.server_config.master.intervals.max_allowed_time_without_keep_alive
                ):
                    keep_alive_logger.error(
                        'No keep alives have been received from {} in the last minute. Disconnecting'.format(
                            client_name
                        ),
                        exc_info=False,
                    )
                    client.transport.close()
            keep_alive_logger.debug('Calculated.')
            await asyncio.sleep(self.server_config.master.intervals.check_worker_last_keep_alive)

    async def performance_test(self):
        """Send a big message to all clients every 3 seconds."""
        while True:
            for client_name, client in self.clients.items():
                try:
                    before = perf_counter()
                    response = await client.send_request(b'echo', b'a' * self.performance)
                    after = perf_counter()
                    self.logger.info(f'Received size: {len(response)} // Time: {after - before}')
                except Exception as e:
                    self.logger.error(f'Error during performance test: {e}')
            await asyncio.sleep(3)

    async def concurrency_test(self):
        """Send lots of messages in a row to all clients. Then rests for 10 seconds."""
        while True:
            before = perf_counter()
            for i in range(self.concurrency):
                for client_name, client in self.clients.items():
                    try:
                        await client.send_request(b'echo', f'concurrency {i} client {client_name}'.encode())
                    except Exception as e:
                        self.logger.error(
                            f'Error during concurrency test ({i + 1}/{self.concurrency}, {client_name}): {e}'
                        )
            after = perf_counter()
            self.logger.info(f'Time sending {self.concurrency} messages: {after - before}')
            await asyncio.sleep(10)

    async def start(self):
        """Start the server and the infinite asynchronous tasks."""
        # Get a reference to the event loop as we plan to use low-level APIs.
        context_tag.set(self.tag)
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop.set_exception_handler(c_common.asyncio_exception_handler)

        ssl_context = c_common.create_ssl_context(
            self.logger,
            ssl.Purpose.CLIENT_AUTH,
            self.server_config.node.ssl.ca,
            self.server_config.node.ssl.cert,
            self.server_config.node.ssl.key,
            self.server_config.node.ssl.keyfile_password,
        )

        try:
            server = await self.loop.create_server(
                protocol_factory=lambda: self.handler_class(
                    server=self, loop=self.loop, logger=self.logger, server_config=self.server_config
                ),
                host=self.server_config.bind_addr,
                port=self.server_config.port,
                ssl=ssl_context,
            )
        except OSError as e:
            raise exception.WazuhClusterError(3007, extra_message=e)

        self.logger.info(f'Serving on {server.sockets[0].getsockname()}')
        self.tasks.append(server.serve_forever)

        async with server:
            # Use asyncio.gather to run both tasks in parallel.
            await asyncio.gather(*map(lambda x: x(), self.tasks))
