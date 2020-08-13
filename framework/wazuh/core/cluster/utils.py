# Copyright (C) 2015-2020, Wazuh Inc.
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
from functools import lru_cache
from glob import glob
from operator import setitem
from os.path import join, exists

from wazuh.core import common
from wazuh.core.configuration import get_ossec_conf
from wazuh.core.exception import WazuhException, WazuhError, WazuhInternalError
from wazuh.core.results import WazuhResult
from wazuh.core.wlogging import WazuhLogger

logger = logging.getLogger('wazuh')
execq_lockfile = join(common.ossec_path, "var/run/.api_execq_lock")


def read_cluster_config(config_file=common.ossec_conf) -> typing.Dict:
    """
    Reads the cluster configuration

    :return: Dictionary with cluster configuration.
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
        config_cluster = get_ossec_conf(section='cluster', conf_file=config_file)['cluster']
    except WazuhException as e:
        if e.code == 1106:
            # if no cluster configuration is present in ossec.conf, return default configuration but disabling it.
            cluster_default_configuration['disabled'] = True
            return cluster_default_configuration
        else:
            raise WazuhError(3006, extra_message=e.message)
    except Exception as e:
        raise WazuhError(3006, extra_message=str(e))

    # if any value is missing from user's cluster configuration, add the default one:
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
                         extra_message="Allowed values for 'disabled' field are 'yes' and 'no'. Found: '{}'"
                         .format(config_cluster['disabled']))

    # if config_cluster['node_name'].upper() == '$HOSTNAME':
    #     # The HOSTNAME environment variable is not always available in os.environ so use socket.gethostname() instead
    #     config_cluster['node_name'] = gethostname()

    # if config_cluster['node_name'].upper() == '$NODE_NAME':
    #     if 'NODE_NAME' in environ:
    #         config_cluster['node_name'] = environ['NODE_NAME']
    #     else:
    #         raise WazuhException(3006, 'Unable to get the $NODE_NAME environment variable')

    # if config_cluster['node_type'].upper() == '$NODE_TYPE':
    #     if 'NODE_TYPE' in environ:
    #         config_cluster['node_type'] = environ['NODE_TYPE']
    #     else:
    #         raise WazuhException(3006, 'Unable to get the $NODE_TYPE environment variable')

    if config_cluster['node_type'] == 'client':
        logger.info("Deprecated node type 'client'. Using 'worker' instead.")
        config_cluster['node_type'] = 'worker'

    return config_cluster


def get_manager_status() -> typing.Dict:
    """
    Returns the Manager processes that are running.

    :return: Dictionary (keys: status, daemon).
    """

    processes = ['ossec-agentlessd', 'ossec-analysisd', 'ossec-authd', 'ossec-csyslogd', 'ossec-dbd', 'ossec-monitord',
                 'ossec-execd', 'ossec-integratord', 'ossec-logcollector', 'ossec-maild', 'ossec-remoted',
                 'ossec-reportd', 'ossec-syscheckd', 'wazuh-clusterd', 'wazuh-modulesd', 'wazuh-db', 'wazuh-apid']

    data, pidfile_regex, run_dir = {}, re.compile(r'.+\-(\d+)\.pid$'), join(common.ossec_path, 'var/run')
    for process in processes:
        pidfile = glob(join(run_dir, f"{process}-*.pid"))
        if exists(join(run_dir, f'{process}.failed')):
            data[process] = 'failed'
        elif exists(join(run_dir, f'.restart')):
            data[process] = 'restarting'
        elif exists(join(run_dir, f'{process}.start')):
            data[process] = 'starting'
        elif pidfile:
            process_pid = pidfile_regex.match(pidfile[0]).group(1)
            # if a pidfile exists but the process is not running, it means the process crashed and
            # wasn't able to remove its own pidfile.
            data[process] = 'running' if exists(join('/proc', process_pid)) else 'failed'
        else:
            data[process] = 'stopped'

    return data


def get_cluster_status() -> typing.Dict:
    """
    Returns the cluster status

    :return: Dictionary with cluster status
    """
    return {"enabled": "no" if read_cluster_config()['disabled'] else "yes",
            "running": "yes" if get_manager_status()['wazuh-clusterd'] == 'running' else "no"}


def manager_restart():
    """
    Restart Wazuh manager.

    :return: Confirmation message.
    """
    lock_file = open(execq_lockfile, 'a+')
    fcntl.lockf(lock_file, fcntl.LOCK_EX)
    try:
        # execq socket path
        socket_path = common.EXECQ
        # msg for restarting Wazuh manager
        msg = 'restart-wazuh '
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

    return WazuhResult({'message': 'Restart request sent'})


@lru_cache()
def get_cluster_items():
    try:
        here = os.path.abspath(os.path.dirname(__file__))
        with open(os.path.join(common.ossec_path, here, 'cluster.json')) as f:
            cluster_items = json.load(f)
        list(map(lambda x: setitem(x, 'permissions', int(x['permissions'], base=0)),
                 filter(lambda x: 'permissions' in x, cluster_items['files'].values())))
        return cluster_items
    except Exception as e:
        raise WazuhError(3005, str(e))


@lru_cache()
def read_config(config_file=common.ossec_conf):
    """ Returns the cluster configuration. """
    return read_cluster_config(config_file=config_file)


# Context vars
context_tag: ContextVar[str] = ContextVar('tag', default='')
context_subtag: ContextVar[str] = ContextVar('subtag', default='')


class ClusterFilter(logging.Filter):
    """
    Adds cluster related information into cluster logs.
    """

    def __init__(self, tag: str, subtag: str, name: str = ''):
        """
        Class constructor

        :param tag: First tag to show in the log - Usually describes class
        :param subtag: Second tag to show in the log - Usually describes function
        :param name: If name is specified, it names a logger which, together with its children, will have its events
                     allowed through the filter. If name is the empty string, allows every event.
        """
        super().__init__(name=name)
        self.tag = tag
        self.subtag = subtag

    def filter(self, record):
        record.tag = context_tag.get() if context_tag.get() != '' else self.tag
        record.subtag = context_subtag.get() if context_subtag.get() != '' else self.subtag
        return True

    def update_tag(self, new_tag: str):
        self.tag = new_tag

    def update_subtag(self, new_subtag: str):
        self.subtag = new_subtag


class ClusterLogger(WazuhLogger):
    """
    Defines the logger used by wazuh-clusterd.
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
