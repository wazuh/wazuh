import asyncio
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

    def __init__(self, loop: uvloop.EventLoopPolicy, on_con_lost: asyncio.Future, name: str):
        """
        Class constructor

        :param name: client's name
        :param loop: asyncio loop
        """
        super().__init__()
        self.loop = loop
        self.name = name
        self.on_con_lost = on_con_lost

    def connection_made(self, transport):
        """
        Defines process of connecting to the server

        :param transport: socket to write data on
        """
        self.transport = transport
        asyncio.gather(self.send_request(command=b'hello', data=self.name.encode()))
        logging.info('Client info sent to server.')

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
        while not self.on_con_lost.done():
            result = await self.send_request(b'echo-c', b'hello from client')
            logging.info(result)
            await asyncio.sleep(3)

    async def performance_test_client(self, test_size):
        while not self.on_con_lost.done():
            before = time.time()
            result = await self.send_request(b'echo', b'a' * test_size)
            after = time.time()
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


async def main():
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG)
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--name', help="Client's name", type=str, dest='name', required=True)
    parser.add_argument('-p', '--performance_test', default=0, type=int, dest='performance_test',
                        help="Perform a performance test against server. Number of bytes to test with.")
    parser.add_argument('-c', '--concurrency_test', default=0, type=int, dest='concurrency_test',
                        help="Perform a concurrency test against server. Number of messages to send in a row.")
    parser.add_argument('-f', '--file', help="Send file to server", type=str, dest='send_file')
    parser.add_argument('-s', '--string', help="Send a large string to the server. Specify string size.",
                        type=int, dest='send_string')
    args = parser.parse_args()

    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(common.asyncio_exception_handler)
    on_con_lost = loop.create_future()

    while True:
        try:
            transport, protocol = await loop.create_connection(lambda: EchoClientProtocol(loop, on_con_lost, args.name),
                                                               '172.17.0.101', 8888)
        except ConnectionRefusedError:
            logging.error("Could not connect to server. Trying again in 10 seconds.")
            await asyncio.sleep(10)
            continue

        if args.performance_test:
            task, task_args = protocol.performance_test_client, (args.performance_test,)
        elif args.concurrency_test:
            task, task_args = protocol.concurrency_test_client, (args.concurrency_test,)
        elif args.send_file:
            task, task_args = protocol.send_file_task, (args.send_file,)
        elif args.send_string:
            task, task_args = protocol.send_string_task, (args.send_string,)
        else:
            task, task_args = protocol.client_echo, tuple()

        # Wait until the protocol signals that the connection
        # is lost and close the transport.
        try:
            await asyncio.gather(on_con_lost, task(*task_args))
        finally:
            transport.close()

        logging.info("The connection has ben closed. Reconnecting in 10 seconds.")
        await asyncio.sleep(10)


try:
    while True:
        try:
            asyncio.run(main())
        except asyncio.CancelledError:
            logging.info("Connection with server has been lost. Reconnecting in 10 seconds.")
            time.sleep(10)
except KeyboardInterrupt:
    logging.info("SIGINT received. Bye!")
