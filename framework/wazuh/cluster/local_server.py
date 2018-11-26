import asyncio
import uvloop
import server
import common
import logging
from typing import Tuple
import json
import cluster
import random


class LocalServerHandler(server.EchoServerHandler):

    def connection_made(self, transport):
        """
        Defines the process of accepting a connection

        :param transport: socket to write data on
        """
        self.name = random.SystemRandom().randint(0, 2 ** 32 - 1)
        logging.info('Connection received in local server. Client name: {}'.format(self.name))
        self.transport = transport
        self.server.clients[self.name] = self

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        if command == b'get_config':
            return self.get_config()
        else:
            return super().process_request(command, data)

    def get_config(self) -> Tuple[bytes, bytes]:
        return b'ok', json.dumps(cluster.read_config()).encode()


class LocalServer(server.EchoServer):

    async def start(self):
        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(common.asyncio_exception_handler)

        try:
            server = await loop.create_unix_server(protocol_factory=lambda: LocalServerHandler(server=self, loop=loop, fernet_key=None),
                                                   path='{}/queue/cluster/c-internal.sock'.format('/var/ossec'))
        except OSError as e:
            logging.error("Could not create server: {}".format(e))
            raise KeyboardInterrupt

        logging.info('Serving on {}'.format(server.sockets[0].getsockname()))

        async with server:
            # use asyncio.gather to run both tasks in parallel
            await asyncio.gather(server.serve_forever(), self.check_clients_keepalive())
