import asyncio
import ssl
import uvloop
import time
import common
import logging
from typing import Tuple


class EchoServerHandler(common.Handler):
    """
    Defines echo server protocol
    """

    def __init__(self, server, loop, fernet_key):
        super().__init__(fernet_key=fernet_key)
        self.server = server
        self.loop = loop
        self.last_keepalive = time.time()

    def connection_made(self, transport):
        """
        Defines the process of accepting a connection

        :param transport: socket to write data on
        """
        peername = transport.get_extra_info('peername')
        logging.info('Connection from {}'.format(peername))
        self.transport = transport
        self.name = None

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
        if data in self.server.clients:
            logging.error("Client {} already present".format(data))
            return b'err', b'Client already present'
        else:
            self.server.clients[data] = self
            self.name = data
            return b'ok', 'Client {} added'.format(data).encode()

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
            logging.info("The client '{}' closed the connection".format(self.name))
            del self.server.clients[self.name]
        else:
            logging.error("Error during handshake with incoming client: {}".format(exc))


class EchoServer:
    """
    Defines an asynchronous echo server.
    """

    def __init__(self, performance_test, concurrency_test, fernet_key: str, enable_ssl: bool):
        self.clients = {}
        self.performance = performance_test
        self.concurrency = concurrency_test
        self.fernet_key = fernet_key
        self.enable_ssl = enable_ssl

    async def check_clients_keepalive(self):
        """
        Task to check the date of the last received keep alives from clients.
        """
        while True:
            curr_timestamp = time.time()
            for client_name, client in self.clients.items():
                if curr_timestamp - client.last_keepalive > 30:
                    logging.error("No keep alives have been received from {} in the last minute. Disconnecting".format(
                        client_name))
                    client.transport.close()
            await asyncio.sleep(30)

    async def echo(self):
        while True:
            for client_name, client in self.clients.items():
                logging.debug("Sending echo to client {}".format(client_name))
                logging.info(await client.send_request(b'echo-m', b'keepalive ' + client_name))
            await asyncio.sleep(3)

    async def performance_test(self):
        while True:
            for client_name, client in self.clients.items():
                before = time.time()
                response = await client.send_request(b'echo', b'a' * self.performance)
                after = time.time()
                logging.info("Received size: {} // Time: {}".format(len(response), after - before))
            await asyncio.sleep(3)

    async def concurrency_test(self):
        while True:
            for i in range(self.concurrency):
                before = time.time()
                for client_name, client in self.clients.items():
                    response = await client.send_request(b'echo',
                                                         'concurrency {} client {}'.format(i, client_name).encode())
                after = time.time()
                logging.info("Time sending {} messages: {}".format(self.concurrency, after - before))
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
            server = await loop.create_server(protocol_factory=lambda: EchoServerHandler(server=self, loop=loop,
                                                                                         fernet_key=self.fernet_key),
                                              host='0.0.0.0', port=8888, ssl=ssl_context)
        except OSError as e:
            logging.error("Could not create server: {}".format(e))
            raise KeyboardInterrupt

        logging.info('Serving on {}'.format(server.sockets[0].getsockname()))

        async with server:
            # use asyncio.gather to run both tasks in parallel
            await asyncio.gather(server.serve_forever(), self.check_clients_keepalive())
