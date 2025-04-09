# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import fcntl
import json
import logging
import os
import re
import socket
import typing
from contextvars import ContextVar
from glob import glob

from wazuh.core import common
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.exception import WazuhInternalError
from wazuh.core.results import WazuhResult
from wazuh.core.utils import temporary_cache
from wazuh.core.wazuh_socket import create_wazuh_socket_message

NO = 'no'
YES = 'yes'
CLIENT_CERT = 'client_cert'
CLIENT_CERT_KEY = 'client_cert_key'
CLIENT_CERT_PASSWORD = 'client_cert_password'
FREQUENCY = 'frequency'
EXCLUDED_NODES = 'excluded_nodes'
AGENT_CHUNK_SIZE = 'agent_chunk_size'
AGENT_RECONNECTION_TIME = 'agent_reconnection_time'
AGENT_RECONNECTION_STABILITY_TIME = 'agent_reconnection_stability_time'
IMBALANCE_TOLERANCE = 'imbalance_tolerance'
REMOVE_DISCONNECTED_NODE_AFTER = 'remove_disconnected_node_after'

logger = logging.getLogger('wazuh')
execq_lockfile = common.WAZUH_RUN / '.api_execq_lock'


@temporary_cache()
def get_manager_status(cache=False) -> typing.Dict:
    """Get the current status of each process of the manager.

    Raises
    ------
    WazuhInternalError(1913)
        If /proc directory is not found or permissions to see its status are not granted.

    Returns
    -------
    data : dict
        Dict whose keys are daemons and the values are the status.
    """
    # Check /proc directory availability
    proc_path = '/proc'
    try:
        os.stat(proc_path)
    except (PermissionError, FileNotFoundError) as e:
        raise WazuhInternalError(1913, extra_message=str(e))

    processes = ['wazuh-server', 'wazuh-engined', 'wazuh-server-management-apid', 'wazuh-comms-apid']

    data, pidfile_regex, run_dir = {}, re.compile(r'.+\-(\d+)\.pid$'), common.WAZUH_RUN
    for process in processes:
        pidfile = glob(os.path.join(run_dir, f'{process}-*.pid'))
        if os.path.exists(os.path.join(run_dir, f'{process}.failed')):
            data[process] = 'failed'
        elif os.path.exists(os.path.join(run_dir, '.restart')):
            data[process] = 'restarting'
        elif os.path.exists(os.path.join(run_dir, f'{process}.start')):
            data[process] = 'starting'
        elif pidfile:
            # Iterate on pidfiles looking for the pidfile which has his pid in /proc,
            # if the loop finishes, all pidfiles exist but their processes are not running,
            # it means each process crashed and was not able to remove its own pidfile.
            data[process] = 'failed'
            for pid in pidfile:
                if os.path.exists(os.path.join(proc_path, pidfile_regex.match(pid).group(1))):
                    data[process] = 'running'
                    break

        else:
            data[process] = 'stopped'

    return data


def get_cluster_status() -> typing.Dict:
    """Get cluster status.

    Returns
    -------
    dict
        Cluster status.
    """
    try:
        cluster_status = {'running': 'yes' if get_manager_status()['wazuh-server'] == 'running' else 'no'}
    except WazuhInternalError:
        cluster_status = {'running': 'no'}

    return cluster_status


def manager_restart() -> WazuhResult:
    """Restart Wazuh manager.

    Send JSON message with the 'restart-wazuh' command to common.EXECQ_SOCKET socket.

    Raises
    ------
    WazuhInternalError(1901)
        If the socket path doesn't exist.
    WazuhInternalError(1902)
        If there is a socket connection error.
    WazuhInternalError(1014)
        If there is a socket communication error.

    Returns
    -------
    WazuhResult
        Confirmation message.
    """
    lock_file = open(execq_lockfile, 'a+')
    fcntl.lockf(lock_file, fcntl.LOCK_EX)
    try:
        # execq socket path
        socket_path = common.EXECQ_SOCKET
        # json msg for restarting Wazuh manager
        msg = json.dumps(
            create_wazuh_socket_message(
                origin={'module': common.origin_module.get()},
                command=common.RESTART_WAZUH_COMMAND,
                parameters={'extra_args': [], 'alert': {}},
            )
        )
        # initialize socket
        if os.path.exists(socket_path):
            try:
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                conn.connect(socket_path)
            except socket.error:
                raise WazuhInternalError(1902)
        else:
            raise WazuhInternalError(1901)

        try:
            conn.send(msg.encode())
            conn.close()
        except socket.error as e:
            raise WazuhInternalError(1014, extra_message=str(e))
    finally:
        fcntl.lockf(lock_file, fcntl.LOCK_UN)
        lock_file.close()

    return WazuhResult({'message': 'Restart request sent'})


# Context vars
context_tag: ContextVar[str] = ContextVar('tag', default='')


def log_subprocess_execution(logger_instance: logging.Logger, logs: dict):
    """Log messages returned by functions that are executed in cluster's subprocesses.

    Parameters
    ----------
    logger_instance: Logger object
        Instance of the used logger.
    logs: dict
        Dict containing messages of different logging level.
    """
    if 'debug' in logs and logs['debug']:
        logger_instance.debug(f'{dict(logs["debug"])}')
    if 'debug2' in logs and logs['debug2']:
        logger_instance.debug2(f'{dict(logs["debug2"])}')
    if 'warning' in logs and logs['warning']:
        logger_instance.warning(f'{dict(logs["warning"])}')
    if 'error' in logs and logs['error']:
        logger_instance.error(f'{dict(logs["error"])}')
    if 'generic_errors' in logs and logs['generic_errors']:
        for error in logs['generic_errors']:
            logger_instance.error(error, exc_info=False)


async def forward_function(
    func: callable,
    f_kwargs: dict = None,
    request_type: str = 'local_master',
    nodes: list = None,
    broadcasting: bool = False,
):
    """Distribute function to master node.

    Parameters
    ----------
    func : callable
        Function to execute on master node.
    f_kwargs : dict
        Function kwargs.
    request_type : str
        Request type.
    nodes : list
        System cluster nodes.
    broadcasting : bool
        Whether the function will be broadcasted or not.

    Returns
    -------
    Return either a dict or `WazuhResult` instance in case the execution did not fail. Return an exception otherwise.
    """
    import concurrent
    from asyncio import run

    from wazuh.core.cluster.dapi.dapi import DistributedAPI

    dapi = DistributedAPI(
        f=func,
        f_kwargs=f_kwargs,
        request_type=request_type,
        is_async=False,
        wait_for_complete=True,
        logger=logger,
        nodes=nodes,
        broadcasting=broadcasting,
    )
    pool = concurrent.futures.ThreadPoolExecutor()
    return pool.submit(run, dapi.distribute_function()).result()


def running_in_master_node() -> bool:
    """Determine if API is running in a master node.

    Returns
    -------
    bool
        True if API is running in master node.
    """
    server_config = CentralizedConfig.get_server_config()
    return server_config.node.type == 'master'


def raise_if_exc(result: object) -> None:
    """Check if a specified object is an exception and raise it.

    Raises
    ------
    Exception

    Parameters
    ----------
    result : object
        Object to be checked.
    """
    if isinstance(result, Exception):
        raise result
