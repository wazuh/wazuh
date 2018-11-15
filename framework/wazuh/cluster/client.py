import asyncio
import common
import logging
import argparse
import time

class EchoClientProtocol(common.Handler):
    """
    Defines a echo client protocol
    """

    def __init__(self, loop, on_con_lost, name):
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
        asyncio.gather(self.send_request(command='hello', data=self.name))
        logging.info('Data sent: {!r}'.format('Hello world!'))


    def connection_lost(self, exc):
        """
        Defines process of closing connection with the server

        :param exc:
        :return:
        """
        logging.info('The server closed the connection')
        logging.info('Stopping tasks')
        self.on_con_lost.set_result(True)
        for task in asyncio.Task.all_tasks():
            task.cancel()
        logging.info('Stop the event loop')


    def process_response(self, command, payload):
        """
        Defines response commands for clients

        :param command: response command received
        :param payload: data received
        :return:
        """
        if command == 'ok-m':
            return "Sucessful response from master: {}".format(payload)
        else:
            return super().process_response(command, payload)


    def process_request(self, command, data):
        """
        Defines commands for clients

        :param command: Received command from client.
        :param data: Received data from client.
        :return: message to send
        """
        if command == "echo-m":
            return self.echo_client(data)
        else:
            return super().process_request(command, data)


    def echo_client(self, data):
        return 'ok-c', data


    async def client_echo(self):
        while not self.on_con_lost.done():
            result = await self.send_request('echo-c','hello from client')
            logging.info(result)
            await asyncio.sleep(3)

    async def performance_test_client(self, test_size):
        while not self.on_con_lost.done():
            before = time.time()
            result = await self.send_request('echo', 'a'*test_size)
            after = time.time()
            logging.info("Received size: {} // Time: {}".format(len(result), after - before))
            await asyncio.sleep(3)


async def main():
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG)
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--name', help="Client's name", type=str, dest='name', required=True)
    parser.add_argument('-p', '--performance_test', default=0, type=int, dest='performance_test',
                        help="Perform a performance test against server. Number of bytes to test with.")
    args = parser.parse_args()

    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()
    on_con_lost = loop.create_future()

    while True:
        try:
            transport, protocol = await loop.create_connection(lambda: EchoClientProtocol(loop, on_con_lost, args.name), '172.17.0.101', 8888)
            break
        except ConnectionRefusedError:
            logging.error("Could not connect to server. Trying again in 10 seconds.")
            await asyncio.sleep(10)

    # Wait until the protocol signals that the connection
    # is lost and close the transport.
    try:
        await asyncio.gather(on_con_lost, protocol.client_echo() if not args.performance_test else protocol.performance_test_client(args.performance_test))
    finally:
        transport.close()

try:
    while True:
        try:
            asyncio.run(main())
        except asyncio.CancelledError:
            logging.info("Connection with server has been lost. Reconnecting in 10 seconds.")
            time.sleep(10)
except KeyboardInterrupt:
    logging.info("SIGINT received. Bye!")
