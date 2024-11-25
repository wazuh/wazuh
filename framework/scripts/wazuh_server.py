#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import asyncio
import logging
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import List

from wazuh.core.common import BIN_ROOT, WAZUH_SHARE, WAZUH_LOG
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.utils import clean_pid_files
from wazuh.core.wlogging import WazuhLogger
from wazuh.core.config.models.server import ServerConfig

BIN_PATH = '/bin'
SERVER_DAEMON_NAME = 'wazuh-server'
COMMS_API_SCRIPT_PATH = WAZUH_SHARE / 'apis' / 'scripts' / 'wazuh_comms_apid.py'
COMMS_API_DAEMON_NAME = 'wazuh-comms-apid'
EMBEDDED_PYTHON_PATH = WAZUH_SHARE / 'framework' / 'python' / 'bin' / 'python3'
ENGINE_BINARY_PATH = BIN_ROOT / 'wazuh-engine'
ENGINE_DAEMON_NAME = 'wazuh-engined'
MANAGEMENT_API_SCRIPT_PATH = WAZUH_SHARE / 'api' / 'scripts' / 'wazuh_apid.py'
MANAGEMENT_API_DAEMON_NAME = 'wazuh-apid'
CLUSTER_LOG = WAZUH_LOG / 'cluster.log'

#
# Aux functions
#


def set_logging(foreground_mode=False, debug_mode=0) -> WazuhLogger:
    """Set cluster logger.

    Parameters
    ----------
    foreground_mode : bool
        Whether the script is running in foreground mode or not.
    debug_mode : int
        Debug mode.

    Returns
    -------
    WazuhLogger
        Cluster logger.
    """
    cluster_logger = cluster_utils.ClusterLogger(
        foreground_mode=foreground_mode,
        log_path='cluster.log',
        debug_level=debug_mode,
        tag='%(asctime)s %(levelname)s: [%(tag)s] [%(subtag)s] %(message)s',
    )
    cluster_logger.setup_logger()
    return cluster_logger


def print_version():
    """Print Wazuh metadata."""
    from wazuh.core.cluster import __author__, __licence__, __version__, __wazuh_name__

    print(f'\n{__wazuh_name__} {__version__} - {__author__}\n\n{__licence__}')


def exit_handler(signum, frame):
    cluster_pid = os.getpid()
    main_logger.info(f'SIGNAL [({signum})-({signal.Signals(signum).name})] received. Shutting down...')

    shutdown_cluster(cluster_pid)

    if callable(original_sig_handler):
        original_sig_handler(signum, frame)
    elif original_sig_handler == signal.SIG_DFL:
        # Call default handler if the original one can't be run
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)


def start_daemon(foreground: bool, name: str, args: List[str]):
    """Start a daemon in a subprocess and validate that there were no errors during its execution.

    Parameters
    ----------
    foreground : bool
        Whether the script is running in foreground mode or not.
    name : str
        Daemon name.
    args : list
        Start command arguments.
    """
    try:
        p = subprocess.Popen(args)
        pid = p.pid
        if foreground or name == ENGINE_DAEMON_NAME:
            returncode = p.poll()
            if returncode not in (0, None):
                raise Exception(f'return code {returncode}')

            if name == ENGINE_DAEMON_NAME:
                pyDaemonModule.create_pid(ENGINE_DAEMON_NAME, pid)
        else:
            returncode = p.wait()
            if returncode != 0:
                raise Exception(f'return code {returncode}')

            pid = pyDaemonModule.get_parent_pid(name)

        main_logger.info(f'Started {name} (pid: {pid})')
    except Exception as e:
        main_logger.error(f'Error starting {name}: {e}')


def start_daemons(foreground: bool, root: bool):
    """Start the engine and the management and communications APIs daemons in subprocesses.

    Parameters
    ----------
    foreground : bool
        Whether the script is running in foreground mode or not.
    root : bool
        Whether the script is running as root or not.
    """
    daemons = {
        ENGINE_DAEMON_NAME: [ENGINE_BINARY_PATH, 'server', 'start'],
        MANAGEMENT_API_DAEMON_NAME: [EMBEDDED_PYTHON_PATH, MANAGEMENT_API_SCRIPT_PATH]
        + (['-r'] if root else [])
        + (['-f'] if foreground else []),
        COMMS_API_DAEMON_NAME: [EMBEDDED_PYTHON_PATH, COMMS_API_SCRIPT_PATH]
        + (['-r'] if root else [])
        + (['-f'] if foreground else []),
    }
    for name, args in daemons.items():
        start_daemon(foreground, name, args)


def shutdown_daemon(name: str):
    """Send a SIGTERM signal to the daemon process.

    Parameters
    ----------
    name : str
        Daemon name.
    """
    ppid = pyDaemonModule.get_parent_pid(name)
    if ppid is not None:
        main_logger.info(f'Shutting down {name} (pid: {ppid})')
        os.kill(ppid, signal.SIGTERM)

        if name == ENGINE_DAEMON_NAME:
            pyDaemonModule.delete_pid(name, ppid)


def shutdown_cluster(cluster_pid: int):
    """Terminate daemons and cluster parent and child processes.

    Parameters
    ----------
    cluster_pid : int
        Cluster process ID.
    """
    daemons = [ENGINE_DAEMON_NAME, MANAGEMENT_API_DAEMON_NAME, COMMS_API_DAEMON_NAME]
    for daemon in daemons:
        shutdown_daemon(daemon)

    # Terminate the cluster
    pyDaemonModule.delete_child_pids(SERVER_DAEMON_NAME, cluster_pid, main_logger)
    pyDaemonModule.delete_pid(SERVER_DAEMON_NAME, cluster_pid)


#
# Master main
#
async def master_main(args: argparse.Namespace, server_config: ServerConfig, logger: WazuhLogger):
    """Start the master node main process.

    Parameters
    ----------
    args : argparse.Namespace
        Script arguments.
    server_config : ServerConfig
        Server configuration.
    logger : WazuhLogger
        Cluster logger.
    """
    from wazuh.core.cluster import local_server, master

    cluster_utils.context_tag.set('Master')

    my_server = master.Master(
        performance_test=args.performance_test,
        concurrency_test=args.concurrency_test,
        logger=logger,
        server_config=server_config,
    )

    # Spawn pool processes
    if my_server.task_pool is not None:
        my_server.task_pool.map(cluster_utils.process_spawn_sleep, range(my_server.task_pool._max_workers))

    my_local_server = local_server.LocalServerMaster(
        performance_test=args.performance_test,
        logger=logger,
        concurrency_test=args.concurrency_test,
        node=my_server,
        server_config=server_config,
    )

    tasks = [my_server, my_local_server]
    #TODO(25554) - Delete in future Issue including references to HAPROXY
    #if not cluster_config.get(cluster_utils.HAPROXY_HELPER, {}).get(cluster_utils.HAPROXY_DISABLED, True):
    #    tasks.append(HAPHelper)
    await asyncio.gather(*[task.start() for task in tasks])


#
# Worker main
#
async def worker_main(args: argparse.Namespace, server_config: ServerConfig, logger: WazuhLogger):
    """Start main process of a worker node.

    Parameters
    ----------
    args : argparse.Namespace
        Script arguments.
    server_config : ServerConfig
        Server configuration.
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
            'Changing the file permissions to 777 will solve this issue.'
        )
        main_logger.warning(
            'The Wazuh cluster will be run without the improvements added in Wazuh 4.3.0 and higher versions.'
        )
        task_pool = None

    while True:
        my_client = worker.Worker(
            performance_test=args.performance_test,
            concurrency_test=args.concurrency_test,
            file=args.send_file,
            string=args.send_string,
            logger=logger,
            server_config=server_config,
            task_pool=task_pool,
        )
        my_local_server = local_server.LocalServerWorker(
            performance_test=args.performance_test,
            logger=logger,
            concurrency_test=args.concurrency_test,
            node=my_client,
            server_config=server_config,
        )
        # Spawn pool processes
        if my_client.task_pool is not None:
            my_client.task_pool.map(cluster_utils.process_spawn_sleep, range(my_client.task_pool._max_workers))
        try:
            await asyncio.gather(my_client.start(), my_local_server.start())
        except asyncio.CancelledError:
            logging.info("Connection with server has been lost. Reconnecting in 10 seconds.")
            await asyncio.sleep(server_config.worker.intervals.connection_retry)


def get_script_arguments() -> argparse.Namespace:
    """Get script arguments.

    Returns
    -------
    argparse.Namespace
        Arguments passed to the script.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('-V', help='Print version', action='store_true', dest='version')
    parser.add_argument(
        '-d',
        help='Enable debug messages. Use twice to increase verbosity.',
        action='count',
        dest='debug_level',
        default=0
    )

    subparsers = parser.add_subparsers(title='subcommands', help='Management operations.')

    start_parser = subparsers.add_parser('start', help='Start Wazuh server.')
    ####################################################################################################################
    # Dev options - Silenced in the help message.
    ####################################################################################################################
    # Performance test - value stored in args.performance_test will be used to send a request of that size in bytes to
    # all clients/to the server.
    start_parser.add_argument('--performance_test', type=int, dest='performance_test', help=argparse.SUPPRESS)
    # Concurrency test - value stored in args.concurrency_test will be used to send that number of requests in a row,
    # without sleeping.
    start_parser.add_argument('--concurrency_test', type=int, dest='concurrency_test', help=argparse.SUPPRESS)
    # Send string test - value stored in args.send_string variable will be used to send a string with that size in bytes
    # to the server. Only implemented in worker nodes.
    start_parser.add_argument('--string', help=argparse.SUPPRESS, type=int, dest='send_string')
    # Send file test - value stored in args.send_file variable is the path of a file to send to the server. Only
    # implemented in worker nodes.
    start_parser.add_argument('--file', help=argparse.SUPPRESS, type=str, dest='send_file')
    ####################################################################################################################
    start_parser.add_argument('-f', help='Run in foreground', action='store_true', dest='foreground')
    start_parser.add_argument('-r', help='Run as root', action='store_true', dest='root')

    start_parser.set_defaults(func=main)

    stop_parser = subparsers.add_parser('stop', help='Stop Wazuh server.')
    stop_parser.set_defaults(func=stop, foreground=True)

    status_parser = subparsers.add_parser('status', help='Show the Wazuh server status.')
    status_parser.set_defaults(func=status)

    return parser


def main():
    """Main function of the wazuh-clusterd script in charge of starting the cluster process."""
    import wazuh.core.cluster.cluster
    from wazuh.core.config.client import CentralizedConfig
    from wazuh.core.authentication import generate_keypair, keypair_exists

    # Set correct permissions on cluster.log file
    if os.path.exists(CLUSTER_LOG):
        os.chown(CLUSTER_LOG, common.wazuh_uid(), common.wazuh_gid())
        os.chmod(CLUSTER_LOG, 0o660)

    try:
        server_config = CentralizedConfig.get_server_config()
    except Exception as e:
        main_logger.error(e)
        sys.exit(1)

    # Clean cluster files from previous executions
    wazuh.core.cluster.cluster.clean_up()
    # Check for unused PID files
    clean_pid_files(SERVER_DAEMON_NAME)

    # Foreground/Daemon
    if not args.foreground:
        pyDaemonModule.pyDaemon()

    # Drop privileges to wazuh
    if not args.root:
        os.setgid(common.wazuh_gid())
        os.setuid(common.wazuh_uid())

    cluster_pid = os.getpid()
    pyDaemonModule.create_pid(SERVER_DAEMON_NAME, cluster_pid)
    if args.foreground:
        print(f'Starting cluster in foreground (pid: {cluster_pid})')

    if server_config.node.type == 'master':
        main_function = master_main

        # Generate JWT signing key pair if it doesn't exist
        if not keypair_exists():
            main_logger.info('Generating JWT signing key pair')
            generate_keypair()
    else:
        main_function = worker_main

    try:
        start_daemons(args.foreground, args.root)

        asyncio.run(main_function(args, server_config, main_logger))
    except KeyboardInterrupt:
        main_logger.info('SIGINT received. Shutting down...')
    except MemoryError:
        main_logger.error("Directory '/tmp' needs read, write & execution " "permission for 'wazuh' user")
    except Exception as e:
        main_logger.error(f'Unhandled exception: {e}')
    finally:
        shutdown_cluster(cluster_pid)


def stop():
    """Stop the Wazuh server running in background."""

    try:
        server_pid = pyDaemonModule.get_wazuh_server_pid(SERVER_DAEMON_NAME)
    except StopIteration:
        main_logger.error('Wazuh server is not running.')
        sys.exit(1)

    shutdown_cluster(server_pid)
    os.kill(server_pid, signal.SIGKILL)


def status():
    """Show the status of the Wazuh server."""

    daemons = [SERVER_DAEMON_NAME, COMMS_API_DAEMON_NAME, MANAGEMENT_API_DAEMON_NAME, ENGINE_DAEMON_NAME]
    running_processes = pyDaemonModule.get_running_processes()

    for daemon in daemons:
        status = 'running'
        if daemon not in running_processes:
            status = 'not running'
        print(f'{daemon} is {status}...')


if __name__ == '__main__':
    import wazuh.core.cluster.utils as cluster_utils
    from wazuh.core import common, pyDaemonModule

    original_sig_handler = signal.signal(signal.SIGTERM, exit_handler)

    parser = get_script_arguments()
    args = parser.parse_args()
    if args.version:
        print_version()
        sys.exit(0)

    # Set logger
    try:
        debug_mode_ = CentralizedConfig.get_server_config().logging.get_level_value()
    except Exception:
        debug_mode_ = 0

    main_logger = set_logging(foreground_mode=getattr(args, 'foreground', False), debug_mode=debug_mode_)

    if hasattr(args, 'func'):
        args.func()
    else:
        parser.print_help()
