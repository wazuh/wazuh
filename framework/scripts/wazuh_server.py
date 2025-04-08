#!/usr/share/wazuh-server/framework/python/bin/python3

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import asyncio
import contextlib
import os
import signal
import subprocess
import sys
import time
from functools import partial
from typing import Any, List

import psutil
from wazuh.core.common import CONFIG_SERVER_SOCKET_PATH, WAZUH_RUN, WAZUH_SHARE, wazuh_gid, wazuh_uid
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.exception import WazuhDaemonError
from wazuh.core.server.unix_server.server import start_unix_server
from wazuh.core.server.utils import (
    ServerLogger,
    context_tag,
    ping_unix_socket,
    print_version,
)
from wazuh.core.task.order import get_orders
from wazuh.core.utils import clean_pid_files, create_wazuh_dir
from wazuh.core.wlogging import WazuhLogger

SERVER_DAEMON_NAME = 'wazuh-server'
COMMS_API_DAEMON_NAME = 'wazuh-comms-apid'
COMMS_API_SCRIPT_PATH = WAZUH_SHARE / 'apis' / 'scripts' / f'{COMMS_API_DAEMON_NAME}.py'
ENGINE_BINARY_PATH = WAZUH_SHARE / 'bin' / 'wazuh-engine'
ENGINE_DAEMON_NAME = 'wazuh-engined'
MANAGEMENT_API_DAEMON_NAME = 'wazuh-server-management-apid'
MANAGEMENT_API_SCRIPT_PATH = WAZUH_SHARE / 'apis' / 'scripts' / f'{MANAGEMENT_API_DAEMON_NAME}.py'


#
# Aux functions
#


def set_logging(debug_mode=0) -> WazuhLogger:
    """Set server logger.

    Parameters
    ----------
    debug_mode : int
        Debug mode.

    Returns
    -------
    WazuhLogger
        Server logger.
    """
    server_logger = ServerLogger(
        debug_level=debug_mode,
        tag='%(asctime)s %(levelname)s: [%(tag)s] [%(subtag)s] %(message)s',
    )
    server_logger.setup_logger()
    return server_logger


def start_daemon(name: str, args: List[str]):
    """Start a daemon in a subprocess and validate that there were no errors during its execution.

    Parameters
    ----------
    name : str
        Daemon name.
    args : list
        Start command arguments.
    """
    main_logger.info(f'Starting {name}')

    try:
        p = subprocess.Popen(args)
        pid = p.pid
        # Wait two seconds to catch any failures during the execution. If the timeout is reached we consider
        # it successful
        returncode = p.wait(timeout=2)
        if returncode != 0:
            raise Exception(f'return code {returncode}')
    except subprocess.TimeoutExpired:
        # The command was executed without errors
        if name == ENGINE_DAEMON_NAME:
            pyDaemonModule.create_pid(ENGINE_DAEMON_NAME, pid)
        main_logger.info(f'Started {name} (pid: {pid})')
    except Exception as e:
        raise WazuhDaemonError(code=1017, extra_message=f'Error starting {name}: {e}')


def start_daemons(root: bool):
    """Start the engine and the management and communications APIs daemons in subprocesses.

    Parameters
    ----------
    root : bool
        Whether the script is running as root or not.
    """
    engine_log_level = {0: 'info', 1: 'debug', 2: 'trace'}

    daemons = {
        ENGINE_DAEMON_NAME: [ENGINE_BINARY_PATH, 'server', '-l', engine_log_level[debug_mode_], 'start'],
        COMMS_API_DAEMON_NAME: [COMMS_API_SCRIPT_PATH] + (['-r'] if root else []),
        MANAGEMENT_API_DAEMON_NAME: [MANAGEMENT_API_SCRIPT_PATH] + (['-r'] if root else []),
    }

    for name, args in daemons.items():
        start_daemon(name, args)


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


def shutdown_server(server_pid: int):
    """Terminate daemons and server parent and child processes.

    Parameters
    ----------
    server_pid : int
        Server process ID.
    """
    daemons = [ENGINE_DAEMON_NAME, MANAGEMENT_API_DAEMON_NAME, COMMS_API_DAEMON_NAME]
    for daemon in daemons:
        shutdown_daemon(daemon)

    main_logger.info('Waiting for daemons shutdown.')
    while pyDaemonModule.check_for_daemons_shutdown(daemons):
        time.sleep(1)

    # Terminate the server
    pyDaemonModule.delete_child_pids(SERVER_DAEMON_NAME, server_pid, main_logger)
    pyDaemonModule.delete_pid(SERVER_DAEMON_NAME, server_pid)


def initialize(args: argparse.Namespace):
    """Start the server instance."""
    tag = 'Server'
    context_tag.set(tag)
    start_unix_server(tag)

    while not ping_unix_socket(CONFIG_SERVER_SOCKET_PATH):
        main_logger.info('Configuration server is not available, retrying...')
        time.sleep(1)

    # Initialize daemons
    start_daemons(args.root)


def get_script_arguments() -> argparse.Namespace:
    """Get script arguments.

    Returns
    -------
    argparse.Namespace
        Arguments passed to the script.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', help='Print version', action='store_true', dest='version')

    subparsers = parser.add_subparsers(title='subcommands', help='Management operations')

    start_parser = subparsers.add_parser('start', help='Start Wazuh server')
    ####################################################################################################################
    start_parser.add_argument('-r', '--root', help='Run as root', action='store_true', dest='root')

    start_parser.set_defaults(func=start)

    stop_parser = subparsers.add_parser('stop', help='Stop Wazuh server')
    stop_parser.set_defaults(func=stop)

    status_parser = subparsers.add_parser('status', help='Show the Wazuh server status')
    status_parser.set_defaults(func=status)

    return parser


def start():  # noqa: C901
    """Start function of the wazuh-server script in charge of starting the server process."""
    with contextlib.suppress(StopIteration):
        server_pid = pyDaemonModule.get_wazuh_server_pid(SERVER_DAEMON_NAME)
        if server_pid and psutil.pid_exists(server_pid):
            print(f'The server is already running on process {server_pid}')
            sys.exit(1)

    # Create /run/wazuh-server
    create_wazuh_dir(WAZUH_RUN)

    # Check for unused PID files
    main_logger.debug('Checking for unused PID files')
    clean_pid_files(SERVER_DAEMON_NAME)

    # Drop privileges to wazuh
    if not args.root:
        os.setgid(wazuh_gid())
        os.setuid(wazuh_uid())

    server_pid = os.getpid()

    pyDaemonModule.create_pid(SERVER_DAEMON_NAME, server_pid)
    signal.signal(signal.SIGTERM, partial(sigterm_handler, server_pid=server_pid))

    main_logger.info(f'Starting server (pid: {server_pid})')
    # Create a strong reference to prevent the tasks from being garbage collected.
    background_tasks = set()
    try:
        initialize(args)
        loop = asyncio.new_event_loop()
        loop.add_signal_handler(signal.SIGTERM, partial(stop_loop, loop))
        background_tasks.add(loop.create_task(get_orders(main_logger)))
        loop.run_until_complete(monitor_server_daemons(loop, psutil.Process(server_pid)))
    except KeyboardInterrupt:
        main_logger.info('SIGINT received. Shutting down...')
    except MemoryError:
        main_logger.error("Directory '/tmp' needs read, write & execution permission for 'wazuh-server' user")
    except WazuhDaemonError as e:
        main_logger.error(e)
    except RuntimeError:
        main_logger.info('Main loop stopped.')
    except Exception as e:
        main_logger.error(f'Unhandled exception: {e}')
    finally:
        shutdown_server(server_pid)


def _get_child_process(processes: List[psutil.Process], proc_name: str) -> psutil.Process:
    """Search for proc_name whithin the list of processes.

    Parameters
    ----------
    processes : List[psutil.Process]
        List of processes to search within.
    proc_name : str
        Name of the process to search.

    Returns
    -------
    psutil.Process
        The found process.
    """
    return [i for i in processes if proc_name[:-1] in i.name()][0]


def _check_children_number(process: psutil.Process, expected_children_number: int) -> bool:
    """Check the process had the expected number of children number.

    Parameters
    ----------
    process : psutil.Process
        Process to get the current number of childre.
    expected_children_number : int
        Expected value to check.

    Returns
    -------
    bool
        True if the process had the expected number of children else False.
    """
    return len(process.children()) == expected_children_number


def check_daemon(processes: list, proc_name: str, children_number: int):
    """Check if the daemon is in the list of processes and has the correct number of children.

    Parameters
    ----------
    processes : list
        List of processes to search within.
    proc_name : str
        Name of the process to check.
    children_number : int
        Expected number of children to check.

    Raises
    ------
    WazuhDaemonError
        When the process does not have the correct number of children process.
    """
    child: psutil.Process = _get_child_process(processes, proc_name)
    if child.status() == psutil.STATUS_ZOMBIE:
        clean_pid_files(proc_name)
        raise WazuhDaemonError(
            code=1017, extra_message=f'Daemon `{proc_name}` is not running, stopping the whole server.'
        )
    if not _check_children_number(child, children_number):
        raise WazuhDaemonError(
            code=1017, extra_message=f'Daemon `{proc_name}` does not have the correct number of children process.'
        )


async def check_for_server_readiness(server_process: psutil.Process, expected_state: dict):
    """Check the server meets the expected daemons requirements at the startup.

    Parameters
    ----------
    server_process : psutil.Process
        Main server process to get current daemons status.
    expected_state : dict
        Expected daemons names and children number.
    """
    while True:
        states = {}
        processes = server_process.children()

        for proc_name, children in expected_state.items():
            try:
                child: psutil.Process = _get_child_process(processes, proc_name)
            except IndexError:
                states.update({proc_name: False})
                continue

            if _check_children_number(child, children):
                states.update({proc_name: True})
            else:
                states.update({proc_name: False})

        if all(states.values()):
            return
        else:
            main_logger.warning(
                f"The Server doesn't meet the expected daemons state: {states}. Sleeping until next checking..."
            )
        await asyncio.sleep(10)


async def monitor_server_daemons(loop: asyncio.BaseEventLoop, server_process: psutil.Process):
    """Monitor the status of the server daemons.

    Parameters
    ----------
    loop : asyncio.BaseEventLoop
        The loop to stop in case any of the daemons does not meet the expected status.
    server_process : int
        Server process to get the children from.
    """
    comms_api_config = CentralizedConfig.get_comms_api_config()
    process_children = {
        MANAGEMENT_API_DAEMON_NAME[:15]: 5,
        COMMS_API_DAEMON_NAME: comms_api_config.workers + 4,
        ENGINE_DAEMON_NAME: 0,
    }

    await check_for_server_readiness(server_process, process_children)

    while True:
        await asyncio.sleep(10)
        main_logger.debug('Checking server daemons status...')
        child_processes = server_process.children()

        try:
            for proc_name, children in process_children.items():
                check_daemon(child_processes, proc_name, children)
        except WazuhDaemonError as error:
            main_logger.error(f'{error.code} Stopping the whole server.')
            stop_loop(loop)


def stop_loop(loop: asyncio.BaseEventLoop):
    """Stop the given asyncio loop.

    Parameters
    ----------
    loop : asyncio.BaseEventLoop
        The loop to stop.
    """
    loop.stop()


def sigterm_handler(signum: int, frame: Any, server_pid: int) -> None:
    """Handle SIGTERM signal shutting down the server.

    Parameters
    ----------
    signum : int
        The signal number received.
    frame : Any
        The current stack frame (unused).
    server_pid : int
        The server process ID used to terminate.
    """
    shutdown_server(server_pid)


def stop():
    """Stop the Wazuh server running in background."""
    try:
        server_pid = pyDaemonModule.get_wazuh_server_pid(SERVER_DAEMON_NAME)
    except StopIteration:
        main_logger.warning('Wazuh server is not running.')
        sys.exit(0)

    os.kill(server_pid, signal.SIGTERM)


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
    from wazuh.core import pyDaemonModule

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

    main_logger = set_logging(debug_mode=debug_mode_)

    if hasattr(args, 'func'):
        args.func()
    else:
        parser.print_help()
