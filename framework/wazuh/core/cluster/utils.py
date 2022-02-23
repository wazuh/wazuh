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
from functools import lru_cache
from glob import glob
from operator import setitem
from os.path import join, exists

from wazuh.core import common, pyDaemonModule
from wazuh.core.configuration import get_ossec_conf
from wazuh.core.exception import WazuhException, WazuhError, WazuhInternalError
from wazuh.core.results import WazuhResult
from wazuh.core.utils import temporary_cache
from wazuh.core.wazuh_socket import create_wazuh_socket_message
from wazuh.core.wlogging import WazuhLogger

logger = logging.getLogger('wazuh')
execq_lockfile = join(common.wazuh_path, "var/run/.api_execq_lock")


def read_cluster_config(config_file=common.ossec_conf, from_import=False) -> typing.Dict:
    """Read cluster configuration from ossec.conf.

    If some fields are missing in the ossec.conf cluster configuration, they are replaced
    with default values.
    If there is no cluster configuration at all, the default configuration is marked as disabled.

    Parameters
    ----------
    config_file : str
        Path to configuration file.
    from_import : bool
        This flag indicates whether this function has been called from a module load (True) or from a function (False).

    Returns
    -------
    config_cluster : dict
        Dictionary with cluster configuration.
    """
    cluster_default_configuration = {
        'disabled': False,
        'node_type': 'master',
        'name': 'wazuh',
        'node_name': 'node01',
        'key': '',
        'port': 1516,
        'bind_addr': '0.0.0.0',
        'nodes': ['NODE_IP'],
        'hidden': 'no'
    }

    try:
        config_cluster = get_ossec_conf(section='cluster', conf_file=config_file, from_import=from_import)['cluster']
    except WazuhException as e:
        if e.code == 1106:
            # If no cluster configuration is present in ossec.conf, return default configuration but disabling it.
            cluster_default_configuration['disabled'] = True
            return cluster_default_configuration
        else:
            raise WazuhError(3006, extra_message=e.message)
    except Exception as e:
        raise WazuhError(3006, extra_message=str(e))

    # If any value is missing from user's cluster configuration, add the default one.
    for value_name in set(cluster_default_configuration.keys()) - set(config_cluster.keys()):
        config_cluster[value_name] = cluster_default_configuration[value_name]

    if isinstance(config_cluster['port'], str) and not config_cluster['port'].isdigit():
        raise WazuhError(3004, extra_message="Cluster port must be an integer.")

    config_cluster['port'] = int(config_cluster['port'])
    if config_cluster['disabled'] == 'no':
        config_cluster['disabled'] = False
    elif config_cluster['disabled'] == 'yes':
        config_cluster['disabled'] = True
    elif not isinstance(config_cluster['disabled'], bool):
        raise WazuhError(3004,
                         extra_message=f"Allowed values for 'disabled' field are 'yes' and 'no'. "
                                       f"Found: '{config_cluster['disabled']}'")

    if config_cluster['node_type'] == 'client':
        logger.info("Deprecated node type 'client'. Using 'worker' instead.")
        config_cluster['node_type'] = 'worker'

    return config_cluster


@temporary_cache()
def get_manager_status(cache=False) -> typing.Dict:
    """Get the current status of each process of the manager.

    Returns
    -------
    data : dict
        Dict whose keys are daemons and the values are the status.
    """
    processes = ['wazuh-agentlessd', 'wazuh-analysisd', 'wazuh-authd', 'wazuh-csyslogd', 'wazuh-dbd', 'wazuh-monitord',
                 'wazuh-execd', 'wazuh-integratord', 'wazuh-logcollector', 'wazuh-maild', 'wazuh-remoted',
                 'wazuh-reportd', 'wazuh-syscheckd', 'wazuh-clusterd', 'wazuh-modulesd', 'wazuh-db', 'wazuh-apid']

    data, pidfile_regex, run_dir = {}, re.compile(r'.+\-(\d+)\.pid$'), join(common.wazuh_path, 'var/run')
    for process in processes:
        pidfile = glob(join(run_dir, f"{process}-*.pid"))
        if exists(join(run_dir, f'{process}.failed')):
            data[process] = 'failed'
        elif exists(join(run_dir, f'.restart')):
            data[process] = 'restarting'
        elif exists(join(run_dir, f'{process}.start')):
            data[process] = 'starting'
        elif pidfile:
            # Iterate on pidfiles looking for the pidfile which has his pid in /proc,
            # if the loop finishes, all pidfiles exist but their processes are not running,
            # it means each process crashed and was not able to remove its own pidfile.
            data[process] = 'failed'
            for pid in pidfile:
                if exists(join('/proc', pidfile_regex.match(pid).group(1))):
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
    return {"enabled": "no" if read_cluster_config()['disabled'] else "yes",
            "running": "yes" if get_manager_status()['wazuh-clusterd'] == 'running' else "no"}


def manager_restart() -> WazuhResult:
    """Restart Wazuh manager.

    Send JSON message with the 'restart-wazuh' command to common.EXECQ socket.

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
        socket_path = common.EXECQ
        # json msg for restarting Wazuh manager
        msg = json.dumps(create_wazuh_socket_message(origin={'module': common.origin_module.get()},
                                                     command=common.RESTART_WAZUH_COMMAND,
                                                     parameters={'extra_args': [], 'alert': {}}))
        # initialize socket
        if exists(socket_path):
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
        read_config.cache_clear()

    return WazuhResult({'message': 'Restart request sent'})


@lru_cache()
def get_cluster_items():
    """Load and return the content of cluster.json file as a dict.

    Returns
    -------
    cluster_items : dict
        Dictionary with the information inside cluster.json file.
    """
    try:
        here = os.path.abspath(os.path.dirname(__file__))
        with open(os.path.join(common.wazuh_path, here, 'cluster.json')) as f:
            cluster_items = json.load(f)
        # Rebase permissions.
        list(map(lambda x: setitem(x, 'permissions', int(x['permissions'], base=0)),
                 filter(lambda x: 'permissions' in x, cluster_items['files'].values())))
        return cluster_items
    except Exception as e:
        raise WazuhError(3005, str(e))


@lru_cache()
def read_config(config_file=common.ossec_conf):
    """Get the cluster configuration.

    Parameters
    ----------
    config_file : str
        Path to configuration file.

    Returns
    -------
    dict
        Dictionary with cluster configuration.
    """
    return read_cluster_config(config_file=config_file)


# Context vars
context_tag: ContextVar[str] = ContextVar('tag', default='')


class ClusterFilter(logging.Filter):
    """
    Add cluster related information into cluster logs.
    """

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
    """
    Define the logger used by wazuh-clusterd.
    """

    def setup_logger(self):
        """
        Set ups cluster logger. In addition to super().setup_logger() this method adds:
            * A filter to add tag and subtags to cluster logs
            * Sets log level based on the "debug_level" parameter received from wazuh-clusterd binary.
        """
        super().setup_logger()
        self.logger.addFilter(ClusterFilter(tag='Cluster', subtag='Main'))
        debug_level = logging.DEBUG2 if self.debug_level == 2 else \
            logging.DEBUG if self.debug_level == 1 else logging.INFO

        self.logger.setLevel(debug_level)


def process_spawn_sleep(child):
    """Task to force the cluster pool spawn all its children and create their PID files.

    Parameters
    ----------
    child: int
        Process child number.
    """
    pid = os.getpid()
    pyDaemonModule.create_pid(f'wazuh-clusterd_child_{child}', pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    # Add a delay to force each child process to create its own PID file, preventing multiple calls
    # executed by the same child
    time.sleep(0.1)


async def forward_function(func: callable, f_kwargs: dict = None):
    """Distribute function to master node.
    Parameters
    ----------
    func : callable
        Function to execute on master node.
    f_kwargs : dict
        Function kwargs.
    Returns
    -------
    Return either a dict or `WazuhResult` instance in case the execution did not fail. Return an exception otherwise.
    """
    from wazuh.core.cluster import local_client
    from wazuh.core.cluster.common import WazuhJSONEncoder, as_wazuh_object

    lc = local_client.LocalClient()

    input_json = {
        'f': func,
        'from_cluster': False,
        'wait_for_complete': False
    }

    f_kwargs and input_json.update({'f_kwargs': f_kwargs})

    # Distribute function to master node
    response = json.loads(await lc.execute(command=b'dapi',
                                           data=json.dumps(input_json, cls=WazuhJSONEncoder).encode(),
                                           wait_for_complete=False),
                          object_hook=as_wazuh_object)

    return response
