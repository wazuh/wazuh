import asyncio
import ssl
from typing import Tuple
import uvloop
import common
import logging
import argparse
import time


class EchoClientProtocol(common.Handler):
    """
    Defines a echo client protocol
    """

    def __init__(self, loop: uvloop.EventLoopPolicy, on_con_lost: asyncio.Future, name: str, fernet_key: str):
        """
        Class constructor

        :param name: client's name
        :param loop: asyncio loop
        """
        super().__init__(fernet_key=fernet_key)
        self.loop = loop
        self.name = name
        self.on_con_lost = on_con_lost
        self.connected = False

    def connection_made(self, transport):
        """
        Defines process of connecting to the server

        :param transport: socket to write data on
        """
        def connection_result(future_result):
            response_msg = future_result.result()[0]
            if response_msg.startswith(b'Error'):
                logging.error("Could not connect to server: {}.".format(response_msg))
                self.transport.close()
            else:
                logging.info("Sucessfully connected to server.")
                self.connected = True

        self.transport = transport
        future_response = asyncio.gather(self.send_request(command=b'hello', data=self.name.encode()))
        future_response.add_done_callback(connection_result)

    def connection_lost(self, exc):
        """
        Defines process of closing connection with the server

        :param exc: either an exception object or None. The latter means a regular EOF is received, or the connection
                    was aborted or closed by this side of the connection.
        """
        logging.info('The server closed the connection' if exc is None
                     else "Connection closed due to an unhandled error")

        if not self.on_con_lost.done():
            self.on_con_lost.set_result(True)
        for task in asyncio.Task.all_tasks():
            task.cancel()

    def process_response(self, command: bytes, payload: bytes) -> bytes:
        """
        Defines response commands for clients

        :param command: response command received
        :param payload: data received
        :return:
        """
        if command == b'ok-m':
            return b"Sucessful response from master: " + payload
        else:
            return super().process_response(command, payload)

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines commands for clients

        :param command: Received command from client.
        :param data: Received data from client.
        :return: message to send
        """
        if command == b"echo-m":
            return self.echo_client(data)
        else:
            return super().process_request(command, data)

    def echo_client(self, data: bytes) -> Tuple[bytes, bytes]:
        return b'ok-c', data

    async def client_echo(self):
        n_attemps = 0  # number of failed attempts to send a keep alive to server
        while not self.on_con_lost.done():
            if self.connected:
                result = await self.send_request(b'echo-c', b'keepalive')
                if result.startswith(b'Error'):
                    n_attemps += 1
                    if n_attemps >= 3:
                        logging.error("Maximum number of failed keep alives reached. Disconnecting.")
                        self.transport.close()
                logging.info(result)
            await asyncio.sleep(29)

    async def performance_test_client(self, test_size):
        while not self.on_con_lost.done():
            before = time.time()
            result = await self.send_request(b'echo', b'a' * test_size)
            after = time.time()
            if len(result) != test_size:
                logging.error(result)
            else:
                logging.info("Received size: {} // Time: {}".format(len(result), after - before))
            await asyncio.sleep(3)

    async def concurrency_test_client(self, n_msgs):
        while not self.on_con_lost.done():
            before = time.time()
            for i in range(n_msgs):
                result = await self.send_request(b'echo', 'concurrency {}'.format(i).encode())
            after = time.time()
            logging.info("Time sending {} messages: {}".format(n_msgs, after - before))
            await asyncio.sleep(10)

    async def send_file_task(self, filename):
        before = time.time()
        response = await self.send_file(filename)
        after = time.time()
        logging.debug(response)
        logging.debug("Time: {}".format(after - before))

    async def send_string_task(self, string_size):
        before = time.time()
        response = await self.send_string(my_str=b'a' * string_size)
        after = time.time()
        logging.debug(response)
        logging.debug("Time: {}".format(after - before))


class EchoClient:
    def __init__(self, name, key, ssl, performance_test, concurrency_test, file, string):
        self.name = name
        self.key = key
        self.ssl = ssl
        self.performance_test = performance_test
        self.concurrency_test = concurrency_test
        self.file = file
        self.string = string

    async def start(self):
        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(common.asyncio_exception_handler)
        on_con_lost = loop.create_future()
        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH) if self.ssl else None

        while True:
            try:
                transport, protocol = await loop.create_connection(protocol_factory=lambda: EchoClientProtocol(loop,
                                                                                                               on_con_lost,
                                                                                                               self.name,
                                                                                                               self.key),
                                                                   host='172.17.0.101', port=8888, ssl=ssl_context)
            except ConnectionRefusedError:
                logging.error("Could not connect to server. Trying again in 10 seconds.")
                await asyncio.sleep(10)
                continue
            except OSError as e:
                logging.error("Could not connect to server: {}. Trying again in 10 seconds.".format(e))
                await asyncio.sleep(10)
                continue

            if self.performance_test:
                task, task_args = protocol.performance_test_client, (self.performance_test,)
            elif self.concurrency_test:
                task, task_args = protocol.concurrency_test_client, (self.concurrency_test,)
            elif self.file:
                task, task_args = protocol.send_file_task, (self.file,)
            elif self.string:
                task, task_args = protocol.send_string_task, (self.string,)
            else:
                task, task_args = protocol.client_echo, tuple()

            # Wait until the protocol signals that the connection
            # is lost and close the transport.
            try:
                await asyncio.gather(on_con_lost, protocol.client_echo(), task(*task_args))
            finally:
                transport.close()

            logging.info("The connection has ben closed. Reconnecting in 10 seconds.")
            await asyncio.sleep(10)
