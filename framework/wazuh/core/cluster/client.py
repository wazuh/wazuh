# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import itertools
import logging
import ssl
import traceback
from time import perf_counter
from typing import List, Tuple

import uvloop
from wazuh.core.cluster import common
from wazuh.core.cluster.utils import context_tag
from wazuh.core.config.models.server import ServerConfig


class AbstractClientManager:
    """Define an abstract client. Manage connection with server."""

    def __init__(
        self,
        server_config: ServerConfig,
        performance_test: int,
        concurrency_test: int,
        file: str,
        string: int,
        logger: logging.Logger = None,
        tag: str = 'Client Manager',
    ):
        """Class constructor.

        Parameters
        ----------
        server_config : ServerConfig
            Object containing server internal variables.
        performance_test : int
            Value for the performance test function.
        concurrency_test : int
            Value for the concurrency test function.
        file : str
            File path for the send_file test function.
        string : int
            String size for the send_string test function.
        logger : Logger object
            Logger to use.
        tag : str
            Log tag.
        """
        self.name = server_config.node.name
        self.server_config = server_config
        self.performance_test = performance_test
        self.concurrency_test = concurrency_test
        self.file = file
        self.string = string
        self.logger = logging.getLogger('wazuh') if not logger else logger
        self.tag = tag
        # Modify filter tags with context vars.
        context_tag.set(self.tag)
        self.tasks = []
        self.handler_class = AbstractClient
        self.client = None
        self.extra_args = {}
        self.loop = asyncio.get_running_loop()

    def add_tasks(self) -> List[Tuple[asyncio.coroutine, Tuple]]:
        """Add client tasks to the task list.

        The client tasks are just test functions made to test the protocol.

        Returns
        -------
        List of tuples
            The first item is the coroutine to run and the second is the arguments it needs.
        """
        if self.performance_test:
            task = self.client.performance_test_client, (self.performance_test,)
        elif self.concurrency_test:
            task = self.client.concurrency_test_client, (self.concurrency_test,)
        elif self.file:
            task = self.client.send_file_task, (self.file,)
        elif self.string:
            task = self.client.send_string_task, (self.string,)
        else:
            return []

        return [task]

    async def start(self):
        """Connect to the server and wait until the connection is closed."""
        # Get a reference to the event loop as we plan to use low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop.set_exception_handler(common.asyncio_exception_handler)
        on_con_lost = self.loop.create_future()

        ssl_context = common.create_ssl_context(
            self.logger,
            ssl.Purpose.SERVER_AUTH,
            self.server_config.node.ssl.ca,
            self.server_config.node.ssl.cert,
            self.server_config.node.ssl.key,
            self.server_config.node.ssl.keyfile_password,
        )

        while True:
            try:
                transport, protocol = await self.loop.create_connection(
                    protocol_factory=lambda: self.handler_class(
                        loop=self.loop,
                        on_con_lost=on_con_lost,
                        name=self.name,
                        logger=self.logger,
                        server_config=self.server_config,
                        manager=self,
                        **self.extra_args,
                    ),
                    host=self.server_config.nodes[0],
                    port=self.server_config.port,
                    ssl=ssl_context,
                )
                self.client = protocol
            except ConnectionRefusedError:
                self.logger.error('Could not connect to master. Trying again in 10 seconds.')
                await asyncio.sleep(self.server_config.worker.intervals.connection_retry)
                continue
            except OSError as e:
                self.logger.error(f'Could not connect to master: {e}. Trying again in 10 seconds.')
                await asyncio.sleep(self.server_config.worker.intervals.connection_retry)
                continue

            self.tasks.extend([(on_con_lost, None), (self.client.client_echo, tuple())] + self.add_tasks())

            # Wait until the protocol signals that the connection is lost and close the transport.
            try:
                await asyncio.gather(*itertools.starmap(lambda x, y: x(*y) if y is not None else x, self.tasks))
            finally:
                transport.close()

            self.logger.info('The connection has been closed. Reconnecting in 10 seconds.')
            await asyncio.sleep(self.server_config.worker.intervals.connection_retry)


class AbstractClient(common.Handler):
    """Define a client protocol. Handle connection with server."""

    def __init__(
        self,
        loop: uvloop.EventLoopPolicy,
        on_con_lost: asyncio.Future,
        name: str,
        logger: logging.Logger,
        manager: AbstractClientManager,
        server_config: ServerConfig,
        tag: str = 'Client',
    ):
        """Class constructor.

        Parameters
        ----------
        on_con_lost : asyncio.Future object
            Low-level callback to notify when the connection has ended.
        name : str
            Client's name.
        logger : Logger object
            Logger to use.
        manager : AbstractClientManager
            The Client manager that created this object.
        server_config : ServerConfig
            Object containing server internal variables.
        tag : str
            Log tag.
        """
        super().__init__(logger=logger, tag=f'{tag} {name}', server_config=server_config)
        self.loop = loop
        self.server = manager
        self.name = name
        self.on_con_lost = on_con_lost
        self.connected = False
        self.client_data = self.name.encode()

    def connection_result(self, future_result):
        """Callback function called when the master sends a response to the hello command sent by the worker.

        Parameters
        ----------
        future_result : asyncio.Future object
            Result of the hello request.
        """
        try:
            result = future_result.result()
            if isinstance(future_result.result()[0], Exception):
                raise result[0]

            self.logger.info('Successfully connected to master.')
            self.connected = True
        except Exception as e:
            self.logger.error(f'Could not connect to master: {str(e)}.')
            self.transport.close()

    def connection_made(self, transport):
        """Define process of connecting to the server.

        Parameters
        ----------
        transport : asyncio.Transport
            Socket to write data on.
        """
        self.transport = transport
        future = asyncio.gather(self.send_request(command=b'hello', data=self.client_data))
        future.add_done_callback(self.connection_result)

    def connection_lost(self, exc):
        """Define process of closing connection with the server.

        Cancel all tasks and set 'on_con_lost' as True if not already.

        Parameters
        ----------
        exc : Exception, None
            'None' means a regular EOF is received, or the connection was aborted or closed
            by this side of the connection.
        """
        if exc is None:
            self.logger.info('The master closed the connection')
        else:
            self.logger.error(
                f"Connection closed due to an unhandled error: {exc}\n"
                f"{''.join(traceback.format_tb(exc.__traceback__))}",
                exc_info=False,
            )

        if not self.on_con_lost.done():
            self.on_con_lost.set_result(True)
        self._cancel_all_tasks()

    def _cancel_all_tasks(self):
        """Cancel all asyncio tasks and clients."""
        for task in asyncio.all_tasks():
            try:
                task.cancel()
            except Exception as e:
                self.logger.error(f'Error cancelling task {task}: {e}')

        for client in list(self.get_manager().local_server.clients.keys()):
            try:
                self.get_manager().local_server.clients[client].close()
                del self.get_manager().local_server.clients[client]
            except Exception as e:
                self.logger.error(f'Error closing client {client}: {e}')

    def process_response(self, command: bytes, payload: bytes) -> bytes:
        """Define response commands for clients.

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
        if command == b'ok-m':
            return b'Successful response from master: ' + payload
        else:
            return super().process_response(command, payload)

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """Define commands available in clients.

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
        if command == b'echo-m':
            return self.echo_client(data)
        else:
            return super().process_request(command, data)

    def echo_client(self, data: bytes) -> Tuple[bytes, bytes]:
        """Handle "echo-m" request.

        Parameters
        ----------
        data : bytes
            Echo message to repeat.

        Returns
        -------
        bytes
            Result.
        data : bytes
            The same message.
        """
        return b'ok-c', data

    async def client_echo(self):
        """Send a 'keepalive' to the server every x seconds, defined by the server_config properties.

        The client will disconnect from the server if more than
        max_failed_keepalive_attempts (defined in server_config) attempts in a row are failed.

        This asyncio task will be started as soon as the client connects to the server and will be always running.
        """
        keep_alive_logger = self.setup_task_logger('Keep Alive')
        # each subtask must have its own local logger defined
        n_attempts = 0  # number of failed attempts to send a keep alive to server
        while not self.on_con_lost.done():
            if self.connected:
                try:
                    result = await self.send_request(b'echo-c', b'keepalive')
                    keep_alive_logger.info(result.decode())
                    n_attempts = 0  # set failed attempts to 0 when the last one was successful
                except Exception as e:
                    keep_alive_logger.error(f'Error sending keep alive: {e}')
                    n_attempts += 1
                    if n_attempts >= self.server_config.worker.retries.max_failed_keepalive_attempts:
                        keep_alive_logger.error('Maximum number of failed keep alives reached. Disconnecting.')
                        self.transport.close()

            await asyncio.sleep(self.server_config.worker.intervals.keep_alive)

    async def performance_test_client(self, test_size: int):
        """Send a request to the server with a big payload.

        Check the master replies with a payload of the same length. Only for development and testing purposes.

        Parameters
        ----------
        test_size : int
            Payload length.
        """
        while not self.on_con_lost.done():
            try:
                before = perf_counter()
                result = await self.send_request(b'echo', b'a' * test_size)
                after = perf_counter()
                if len(result) != test_size:
                    self.logger.error(result, exc_info=False)
                else:
                    self.logger.info(f'Received size: {len(result)} // Time: {after - before}')
            except Exception as e:
                self.logger.error(f'Error during performance test: {e}')
            await asyncio.sleep(3)

    async def concurrency_test_client(self, n_msgs: int):
        """Send lots of requests to the server at the same time.

        Measure the time the server needed to reply all requests. Only for development and testing purposes.

        Parameters
        ----------
        n_msgs : int
            Number of requests to send.
        """
        while not self.on_con_lost.done():
            try:
                before = perf_counter()
                for i in range(n_msgs):
                    await self.send_request(b'echo', f'concurrency {i}'.encode())
                after = perf_counter()
                self.logger.info(f'Time sending {n_msgs} messages: {after - before}')
            except Exception as e:
                self.logger.error(f'Error during concurrency test: {e}')
            await asyncio.sleep(10)

    async def send_file_task(self, filename: str):
        """Test the send_file protocol.

        Only for development and testing purposes.

        Parameters
        ----------
        filename : str
            Filename to send.
        """
        before = perf_counter()
        response = await self.send_file(filename)
        after = perf_counter()
        self.logger.debug(response)
        self.logger.debug(f'Time: {after - before}')

    async def send_string_task(self, string_size: int):
        """Test the send big string protocol.

        Only for development and testing purposes.

        Parameters
        ----------
        string_size : int
            String length.
        """
        before = perf_counter()
        response = await self.send_string(my_str=b'a' * string_size)
        after = perf_counter()
        self.logger.debug(response)
        self.logger.debug(f'Time: {after - before}')
