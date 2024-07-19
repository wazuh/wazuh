#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import asyncio
import logging
import os
import signal
import sys

from wazuh.core.utils import clean_pid_files
from wazuh.core.wlogging import WazuhLogger

#
# Aux functions
#

def set_logging(foreground_mode=False, debug_mode=0) -> WazuhLogger:
    """Set cluster logger.

    Parameters
    ----------
    foreground_mode : bool
        Whether to log in the standard output or not.
    debug_mode : int
        Debug mode.

    Returns
    -------
    WazuhLogger
        Cluster logger.
    """
    cluster_logger = cluster_utils.ClusterLogger(foreground_mode=foreground_mode, log_path='logs/cluster.log',
                                                 debug_level=debug_mode,
                                                 tag='%(asctime)s %(levelname)s: [%(tag)s] [%(subtag)s] %(message)s')
    cluster_logger.setup_logger()
    return cluster_logger


def print_version():
    """Print Wazuh metadata."""
    from wazuh.core.cluster import __author__, __licence__, __version__, __wazuh_name__
    print(f"\n{__wazuh_name__} {__version__} - {__author__}\n\n{__licence__}")


def exit_handler(signum, frame):
    cluster_pid = os.getpid()
    main_logger.info(f'SIGNAL [({signum})-({signal.Signals(signum).name})] received. Exit...')

    # Terminate cluster's child processes
    pyDaemonModule.delete_child_pids('wazuh-clusterd', cluster_pid, main_logger)

    # Remove cluster's pidfile
    pyDaemonModule.delete_pid('wazuh-clusterd', cluster_pid)

    if callable(original_sig_handler):
        original_sig_handler(signum, frame)
    elif original_sig_handler == signal.SIG_DFL:
        # Call default handler if the original one can't be run
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)


#
# Master main
#
async def master_main(args: argparse.Namespace, cluster_config: dict, cluster_items: dict, logger: WazuhLogger):
    """Start main process of the master node.

    Parameters
    ----------
    args : argparse.Namespace
        Script arguments.
    cluster_config : dict
        Cluster configuration.
    cluster_items : dict
        Content of the cluster.json file.
    logger : WazuhLogger
        Cluster logger.
    """
    from wazuh.core.cluster import local_server, master
    from wazuh.core.cluster.hap_helper.hap_helper import HAPHelper

    cluster_utils.context_tag.set('Master')
    my_server = master.Master(performance_test=args.performance_test, concurrency_test=args.concurrency_test,
                              configuration=cluster_config, enable_ssl=args.ssl, logger=logger,
                              cluster_items=cluster_items)
    # Spawn pool processes
    if my_server.task_pool is not None:
        my_server.task_pool.map(cluster_utils.process_spawn_sleep, range(my_server.task_pool._max_workers))

    my_local_server = local_server.LocalServerMaster(performance_test=args.performance_test, logger=logger,
                                                     concurrency_test=args.concurrency_test, node=my_server,
                                                     configuration=cluster_config, enable_ssl=args.ssl,
                                                     cluster_items=cluster_items)
    tasks = [my_server, my_local_server]
    if not cluster_config.get(cluster_utils.HAPROXY_HELPER, {}).get(cluster_utils.HAPROXY_DISABLED, True):
        tasks.append(HAPHelper)
    await asyncio.gather(*[task.start() for task in tasks])


#
# Worker main
#
async def worker_main(args: argparse.Namespace, cluster_config: dict, cluster_items: dict, logger: WazuhLogger):
    """Start main process of a worker node.

    Parameters
    ----------
    args : argparse.Namespace
        Script arguments.
    cluster_config : dict
        Cluster configuration.
    cluster_items : dict
        Content of the cluster.json file.
    logger : WazuhLogger
        Cluster logger.
    """
    from concurrent.futures import ProcessPoolExecutor

    from wazuh.core.cluster import local_server, worker
    cluster_utils.context_tag.set('Worker')

    # Pool is defined here so the child process is not recreated when the connection with master node is broken.
    try:
        task_pool = ProcessPoolExecutor(max_workers=1)
    # Handle exception when the user running Wazuh cannot access /dev/shm
    except (FileNotFoundError, PermissionError):
        main_logger.warning(
            "In order to take advantage of Wazuh 4.3.0 cluster improvements, the directory '/dev/shm' must be "
            "accessible by the 'wazuh' user. Check that this file has permissions to be accessed by all users. "
            "Changing the file permissions to 777 will solve this issue.")
        main_logger.warning(
            "The Wazuh cluster will be run without the improvements added in Wazuh 4.3.0 and higher versions.")
        task_pool = None

    while True:
        my_client = worker.Worker(configuration=cluster_config, enable_ssl=args.ssl,
                                  performance_test=args.performance_test, concurrency_test=args.concurrency_test,
                                  file=args.send_file, string=args.send_string, logger=logger,
                                  cluster_items=cluster_items, task_pool=task_pool)
        my_local_server = local_server.LocalServerWorker(performance_test=args.performance_test, logger=logger,
                                                         concurrency_test=args.concurrency_test, node=my_client,
                                                         configuration=cluster_config, enable_ssl=args.ssl,
                                                         cluster_items=cluster_items)
        # Spawn pool processes
        if my_client.task_pool is not None:
            my_client.task_pool.map(cluster_utils.process_spawn_sleep, range(my_client.task_pool._max_workers))
        try:
            await asyncio.gather(my_client.start(), my_local_server.start())
        except asyncio.CancelledError:
            logging.info("Connection with server has been lost. Reconnecting in 10 seconds.")
            await asyncio.sleep(cluster_items['intervals']['worker']['connection_retry'])


def get_script_arguments() -> argparse.Namespace:
    """Get script arguments.

    Returns
    -------
    argparse.Namespace
        Arguments passed to the script.
    """

    parser = argparse.ArgumentParser()
    ####################################################################################################################
    # Dev options - Silenced in the help message.
    ####################################################################################################################
    # Performance test - value stored in args.performance_test will be used to send a request of that size in bytes to
    # all clients/to the server.
    parser.add_argument('--performance_test', type=int, dest='performance_test', help=argparse.SUPPRESS)
    # Concurrency test - value stored in args.concurrency_test will be used to send that number of requests in a row,
    # without sleeping.
    parser.add_argument('--concurrency_test', type=int, dest='concurrency_test', help=argparse.SUPPRESS)
    # Send string test - value stored in args.send_string variable will be used to send a string with that size in bytes
    # to the server. Only implemented in worker nodes.
    parser.add_argument('--string', help=argparse.SUPPRESS, type=int, dest='send_string')
    # Send file test - value stored in args.send_file variable is the path of a file to send to the server. Only
    # implemented in worker nodes.
    parser.add_argument('--file', help=argparse.SUPPRESS, type=str, dest='send_file')
    ####################################################################################################################
    parser.add_argument('--ssl', help="Enable communication over SSL", action='store_true', dest='ssl', default=False)
    parser.add_argument('-f', help="Run in foreground", action='store_true', dest='foreground')
    parser.add_argument('-d', help="Enable debug messages. Use twice to increase verbosity.", action='count',
                        dest='debug_level')
    parser.add_argument('-V', help="Print version", action='store_true', dest="version")
    parser.add_argument('-r', help="Run as root", action='store_true', dest='root')
    parser.add_argument('-t', help="Test configuration", action='store_true', dest='test_config')
    parser.add_argument('-c', help="Configuration file to use", type=str, metavar='config', dest='config_file',
                        default=common.OSSEC_CONF)

    return parser


def main():
    """Main function of the wazuh-clusterd script in charge of starting the cluster process."""
    import wazuh.core.cluster.cluster

    # Set correct permissions on cluster.log file
    if os.path.exists(f'{common.WAZUH_PATH}/logs/cluster.log'):
        os.chown(f'{common.WAZUH_PATH}/logs/cluster.log', common.wazuh_uid(), common.wazuh_gid())
        os.chmod(f'{common.WAZUH_PATH}/logs/cluster.log', 0o660)

    try:
        cluster_configuration = cluster_utils.read_config(config_file=args.config_file)
    except Exception as e:
        main_logger.error(e)
        sys.exit(1)

    if cluster_configuration['disabled']:
        sys.exit(0)
    try:
        wazuh.core.cluster.cluster.check_cluster_config(cluster_configuration)
    except Exception as e:
        main_logger.error(e)
        sys.exit(1)

    if args.test_config:
        sys.exit(0)

    # Clean cluster files from previous executions
    wazuh.core.cluster.cluster.clean_up()

    # Check for unused PID files
    clean_pid_files('wazuh-clusterd')

    # Foreground/Daemon
    if not args.foreground:
        pyDaemonModule.pyDaemon()

    # Drop privileges to wazuh
    if not args.root:
        os.setgid(common.wazuh_gid())
        os.setuid(common.wazuh_uid())

    pid = os.getpid()
    pyDaemonModule.create_pid('wazuh-clusterd', pid)
    if args.foreground:
        print(f"Starting cluster in foreground (pid: {pid})")

    main_function = master_main if cluster_configuration['node_type'] == 'master' else worker_main
    try:
        asyncio.run(main_function(args, cluster_configuration, cluster_items, main_logger))
    except KeyboardInterrupt:
        main_logger.info("SIGINT received. Bye!")
    except MemoryError:
        main_logger.error("Directory '/tmp' needs read, write & execution "
                          "permission for 'wazuh' user")
    except Exception as e:
        main_logger.error(f"Unhandled exception: {e}")
    finally:
        pyDaemonModule.delete_child_pids('wazuh-clusterd', pid, main_logger)
        pyDaemonModule.delete_pid('wazuh-clusterd', pid)


if __name__ == '__main__':
    import wazuh.core.cluster.utils as cluster_utils
    from wazuh.core import common, configuration, pyDaemonModule

    cluster_items = cluster_utils.get_cluster_items()
    original_sig_handler = signal.signal(signal.SIGTERM, exit_handler)

    args = get_script_arguments().parse_args()
    if args.version:
        print_version()
        sys.exit(0)

    # Set logger
    try:
        debug_mode_ = configuration.get_internal_options_value('wazuh_clusterd', 'debug', 2, 0) or args.debug_level
    except Exception:
        debug_mode_ = 0

    main_logger = set_logging(foreground_mode=args.foreground, debug_mode=debug_mode_)
    main()
