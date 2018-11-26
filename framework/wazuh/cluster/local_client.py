import asyncio
import logging
import argparse
from client import EchoClient, EchoClientProtocol
import time
import uvloop


class LocalClient(EchoClient):

    async def get_config(self):
        response = await self.client.send_request(b'get_config', b'')
        logging.info("Response: {}".format(response))

    async def start(self):
        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_running_loop()
        on_con_lost = loop.create_future()

        try:
            transport, protocol = await loop.create_unix_connection(
                                protocol_factory=lambda: EchoClientProtocol(loop, on_con_lost, self.name, self.key),
                                path='{}/queue/cluster/c-internal.sock'.format('/var/ossec'))
        except ConnectionRefusedError:
            logging.error("Could not connect to server.")
            return
        except OSError as e:
            logging.error("Could not connect to server: {}.".format(e))
            return

        self.client = protocol

        try:
            await asyncio.gather(on_con_lost, self.get_config())
        finally:
            transport.close()


async def main():
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG)
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--name', help="Client's name", type=str, dest='name', required=True)
    args = parser.parse_args()

    client = LocalClient(args.name, None, False, 0, 0, '', 0)

    await client.start()


try:
    while True:
        try:
            asyncio.run(main())
        except asyncio.CancelledError:
            logging.info("Connection with server has been lost. Reconnecting in 10 seconds.")
            time.sleep(10)
except KeyboardInterrupt:
    logging.info("SIGINT received. Bye!")
