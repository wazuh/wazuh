import asyncio
import logging
import argparse
from client import EchoClient
import time


async def main():
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG)
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--name', help="Client's name", type=str, dest='name', required=True)
    parser.add_argument('-k', '--key', help="Cryptography key", type=str, dest='key', default='')
    parser.add_argument('-p', '--performance_test', default=0, type=int, dest='performance_test',
                        help="Perform a performance test against server. Number of bytes to test with.")
    parser.add_argument('-c', '--concurrency_test', default=0, type=int, dest='concurrency_test',
                        help="Perform a concurrency test against server. Number of messages to send in a row.")
    parser.add_argument('-f', '--file', help="Send file to server", type=str, dest='send_file')
    parser.add_argument('-s', '--string', help="Send a large string to the server. Specify string size.",
                        type=int, dest='send_string')
    parser.add_argument('--ssl', help="Enable communication over SSL", action='store_true', dest='ssl')
    args = parser.parse_args()

    client = EchoClient(args.name, args.key, args.ssl, args.performance_test, args.concurrency_test, args.send_file,
                        args.send_string)

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
