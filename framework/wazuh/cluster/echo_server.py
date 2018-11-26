import asyncio
import logging
import argparse
from server import EchoServer
from local_server import LocalServer


async def main():
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--performance_test', default=0, type=int, dest='performance_test',
                        help="Perform a performance test against all clients. Number of bytes to test with.")
    parser.add_argument('-c', '--concurrency_test', default=0, type=int, dest='concurrency_test',
                        help="Perform a concurrency test against all clients. Number of messages to send in a row to "
                             "each client.")
    parser.add_argument('-k', '--key', help="Cryptography key", type=str, dest='key', default='')
    parser.add_argument('--ssl', help="Enable communication over SSL", action='store_true', dest='ssl')

    args = parser.parse_args()

    server = EchoServer(args.performance_test, args.concurrency_test, args.key, args.ssl)
    local_server = LocalServer(args.performance_test, args.concurrency_test, args.key, args.ssl)
    await asyncio.gather(server.start(), local_server.start())


try:
    asyncio.run(main())
except KeyboardInterrupt:
    logging.info("SIGINT received. Bye!")
