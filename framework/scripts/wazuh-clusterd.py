#!/var/ossec/python/bin/python3

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import logging
import asyncio
import argparse
from wazuh.cluster import cluster, __version__, __author__, __ossec_name__, __licence__, server, local_server, client
from wazuh import common


#
# Aux functions
#
def set_logging(foreground_mode=False, debug_mode=0):
    logger = logging.getLogger()
    # configure logger
    fh = cluster.CustomFileRotatingHandler(filename="{}/logs/cluster.log".format(common.ossec_path), when='midnight')
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s: [%(tag)-15s] %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    if foreground_mode:
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    logger.addFilter(cluster.ClusterFilter(tag='Main'))

    # add a new debug level
    logging.DEBUG2 = 5

    def debug2(self, message, *args, **kws):
        if self.isEnabledFor(logging.DEBUG2):
            self._log(logging.DEBUG2, message, args, **kws)

    def error(self, msg, *args, **kws):
        if self.isEnabledFor(logging.ERROR):
            kws['exc_info'] = self.isEnabledFor(logging.DEBUG2)
            self._log(logging.ERROR, msg, args, **kws)

    logging.addLevelName(logging.DEBUG2, "DEBUG2")

    logging.Logger.debug2 = debug2
    logging.Logger.error = error

    debug_level = logging.DEBUG2 if debug_mode == 2 else logging.DEBUG if \
                  debug_mode == 1 else logging.INFO

    logger.setLevel(debug_level)
    return logger


def print_version():
    print("\n{} {} - {}\n\n{}".format(__ossec_name__, __version__, __author__, __licence__))


#
# Master main
#
async def master_main(args):
    my_server = server.AbstractServer(args.performance_test, args.concurrency_test, args.key, args.ssl)
    my_local_server = local_server.LocalServer(performance_test=args.performance_test,
                                               concurrency_test=args.concurrency_test, fernet_key=args.key,
                                               enable_ssl=args.ssl)
    await asyncio.gather(my_server.start(), my_local_server.start())


#
# Worker main
#
async def worker_main(args):
    my_local_server = local_server.LocalServer(performance_test=args.performance_test,
                                               concurrency_test=args.concurrency_test, fernet_key=args.key,
                                               enable_ssl=args.ssl)
    while True:
        my_client = client.AbstractClientManager(args.name, args.key, args.ssl, args.performance_test,
                                                 args.concurrency_test, args.send_file, args.send_string)
        try:
            await asyncio.gather(my_client.start(), my_local_server.start())
        except asyncio.CancelledError:
            logging.info("Connection with server has been lost. Reconnecting in 10 seconds.")
            await asyncio.sleep(10)


#
# Main
#
async def main():
    logger = set_logging(True, 2)

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--performance_test', default=0, type=int, dest='performance_test',
                        help="Perform a performance test against all clients. Number of bytes to test with.")
    parser.add_argument('-c', '--concurrency_test', default=0, type=int, dest='concurrency_test',
                        help="Perform a concurrency test against all clients. Number of messages to send in a row to "
                             "each client.")
    parser.add_argument('-k', '--key', help="Cryptography key", type=str, dest='key', default='')
    parser.add_argument('-t', '--type', help="Node type", type=str, dest='type', required=True, choices=('master',
                                                                                                         'worker'))
    parser.add_argument('--ssl', help="Enable communication over SSL", action='store_true', dest='ssl')
    parser.add_argument('-n', '--name', help="Client's name", type=str, dest='name', required=True)
    parser.add_argument('-f', '--file', help="Send file to server", type=str, dest='send_file')
    parser.add_argument('-s', '--string', help="Send a large string to the server. Specify string size.",
                        type=int, dest='send_string')

    args = parser.parse_args()
    main_function = master_main if args.type == 'master' else worker_main
    await main_function(args)

try:
    asyncio.run(main())
except KeyboardInterrupt:
    logging.info("SIGINT received. Bye!")


