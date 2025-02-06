# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import fcntl
import json
import logging
import os
import re
import signal
import socket
import time
import typing
from contextvars import ContextVar
from glob import glob
from pathlib import Path

from wazuh.core import common, pyDaemonModule
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.exception import WazuhError, WazuhHAPHelperError, WazuhInternalError
from wazuh.core.results import WazuhResult
from wazuh.core.utils import temporary_cache
from wazuh.core.wazuh_socket import create_wazuh_socket_message
from wazuh.core.wlogging import WazuhLogger

NO = 'no'
YES = 'yes'
HAPROXY_HELPER = 'haproxy_helper'
HAPROXY_DISABLED = 'haproxy_disabled'
HAPROXY_ADDRESS = 'haproxy_address'
HAPROXY_PORT = 'haproxy_port'
HAPROXY_PROTOCOL = 'haproxy_protocol'
HAPROXY_USER = 'haproxy_user'
HAPROXY_PASSWORD = 'haproxy_password'
HAPROXY_BACKEND = 'haproxy_backend'
HAPROXY_RESOLVER = 'haproxy_resolver'
HAPROXY_CERT = 'haproxy_cert'
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

# TODO(25554) - Delete HAPROXY Config
HELPER_DEFAULTS = {
    HAPROXY_PORT: 5555,
    HAPROXY_PROTOCOL: 'http',
    HAPROXY_BACKEND: 'wazuh_reporting',
    HAPROXY_RESOLVER: None,
    HAPROXY_CERT: True,
    CLIENT_CERT: None,
    CLIENT_CERT_KEY: None,
    CLIENT_CERT_PASSWORD: None,
    EXCLUDED_NODES: [],
    FREQUENCY: 60,
    AGENT_CHUNK_SIZE: 300,
    AGENT_RECONNECTION_TIME: 5,
    AGENT_RECONNECTION_STABILITY_TIME: 60,
    IMBALANCE_TOLERANCE: 0.1,
    REMOVE_DISCONNECTED_NODE_AFTER: 240,
}


def ping_unix_socket(socket_path: Path, timeout: int = 1):
    """Ping a UNIX socket to check if it's available.

    Parameters
    ----------
    socket_path : Path
        Path to the UNIX socket file.
    timeout : int
        Connection timeout in seconds.

    Returns
    -------
    bool
        True if the socket is reachable, False otherwise.
    """
    if not socket_path.exists():
        return False

    try:
        # Create a testing UNIX socket client to connect to the server socket.
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect(str(socket_path))
        client.close()
        return True
    except (socket.timeout, socket.error):
        return False


def _parse_haproxy_helper_integer_values(helper_config: dict) -> dict:
    """Parse HAProxy helper integer values.

    Parameters
    ----------
    helper_config : dict
        Configuration to parse.

    Returns
    -------
    dict
        Parsed configuration with integer values.

    Raises
    ------
    WazuhError (3004)
        If some value has an invalid type.
    """
    for field in [
        HAPROXY_PORT,
        FREQUENCY,
        AGENT_RECONNECTION_STABILITY_TIME,
        AGENT_RECONNECTION_TIME,
        AGENT_CHUNK_SIZE,
        REMOVE_DISCONNECTED_NODE_AFTER,
    ]:
        if helper_config.get(field):
            try:
                helper_config[field] = int(helper_config[field])
            except ValueError:
                raise WazuhError(3004, extra_message=f'HAProxy Helper {field} must be an integer.')
    return helper_config


def _parse_haproxy_helper_float_values(helper_config: dict) -> dict:
    """Parse HAProxy helper float values.

    Parameters
    ----------
    helper_config : dict
        Configuration to parse.

    Returns
    -------
    dict
        Parsed configuration with float values.

    Raises
    ------
    WazuhError (3004)
        If some value has an invalid type.
    """
    for field in [IMBALANCE_TOLERANCE]:
        if helper_config.get(field):
            try:
                helper_config[field] = float(helper_config[field])
            except ValueError:
                raise WazuhError(3004, extra_message=f'HAProxy Helper {field} must be a float.')
    return helper_config


def parse_haproxy_helper_config(helper_config: dict) -> dict:
    """Parse HAProxy helper configuration section.

    Parameters
    ----------
    helper_config : dict
        Configuration to parse.

    Returns
    -------
    dict
        Parsed configuration for HAProxy Helper.

    Raises
    ------
    WazuhError (3004)
        If some value has an invalid type.
    WazuhHAPHelperError (3042)
        If the used protocol is HTTPS and the HAProxy certificate is not defined.
    """
    # If any value is missing from user's cluster configuration, add the default one.
    for value_name in set(HELPER_DEFAULTS.keys()) - set(helper_config.keys()):
        helper_config[value_name] = HELPER_DEFAULTS[value_name]

    if helper_config[HAPROXY_DISABLED] == NO:
        helper_config[HAPROXY_DISABLED] = False
    elif helper_config[HAPROXY_DISABLED] == YES:
        helper_config[HAPROXY_DISABLED] = True

    helper_config = _parse_haproxy_helper_integer_values(helper_config)
    helper_config = _parse_haproxy_helper_float_values(helper_config)

    # When the used protocol is HTTPS and the HAProxy certificate is not defined, an error is raised.
    # If the client certificate info is not declared and the tls_ca parameter in the Dataplane API configuration is set,
    # the communication fails
    if helper_config[HAPROXY_PROTOCOL].lower() == 'https' and type(helper_config[HAPROXY_CERT]) is bool:
        raise WazuhHAPHelperError(3042, extra_message='HAProxy certificate file required in the haproxy_cert parameter')

    return helper_config


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


class ClusterFilter(logging.Filter):
    """Add cluster related information into cluster logs."""

    def __init__(self, tag: str, subtag: str, name: str = ''):
        """Class constructor.

        Parameters
        ----------
        tag : str
            First tag to show in the log - Usually describes class.
        subtag : str
            Second tag to show in the log - Usually describes function.
        name : str
            If name is specified, it names a logger which, together with its children, will have its events
            allowed through the filter. If name is the empty string, allows every event.
        """
        super().__init__(name=name)
        self.tag = tag
        self.subtag = subtag

    def filter(self, record):
        record.tag = context_tag.get() if context_tag.get() != '' else self.tag
        record.subtag = self.subtag
        return True

    def update_tag(self, new_tag: str):
        self.tag = new_tag

    def update_subtag(self, new_subtag: str):
        self.subtag = new_subtag


class ClusterLogger(WazuhLogger):
    """Define the logger used by wazuh-clusterd."""

    def setup_logger(self):
        """Set ups cluster logger. In addition to super().setup_logger() this method adds:
        * A filter to add tag and subtags to cluster logs
        * Sets log level based on the "debug_level" parameter received from wazuh-clusterd binary.
        """
        super().setup_logger()
        self.logger.addFilter(ClusterFilter(tag='Cluster', subtag='Main'))
        debug_level = (
            logging.DEBUG2 if self.debug_level == 2 else logging.DEBUG if self.debug_level == 1 else logging.INFO
        )

        self.logger.setLevel(debug_level)


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
        logger_instance.debug(f"{dict(logs['debug'])}")
    if 'debug2' in logs and logs['debug2']:
        logger_instance.debug2(f"{dict(logs['debug2'])}")
    if 'warning' in logs and logs['warning']:
        logger_instance.warning(f"{dict(logs['warning'])}")
    if 'error' in logs and logs['error']:
        logger_instance.error(f"{dict(logs['error'])}")
    if 'generic_errors' in logs and logs['generic_errors']:
        for error in logs['generic_errors']:
            logger_instance.error(error, exc_info=False)


def process_spawn_sleep(child):
    """Task to force the cluster pool spawn all its children and create their PID files.

    Parameters
    ----------
    child: int
        Process child number.
    """
    pid = os.getpid()
    # TODO: 26590 - Use a parameter to set the child name.
    pyDaemonModule.create_pid(f'wazuh-server_child_{child}', pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    # Add a delay to force each child process to create its own PID file, preventing multiple calls
    # executed by the same child
    time.sleep(0.1)


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


def print_version():
    from wazuh.core.cluster import __author__, __licence__, __version__, __wazuh_name__

    print('\n{} {} - {}\n\n{}'.format(__wazuh_name__, __version__, __author__, __licence__))
