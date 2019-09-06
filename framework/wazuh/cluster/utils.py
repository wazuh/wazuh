# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import fcntl
import logging
import re
import socket
import typing
from glob import glob
from os.path import join, exists

import wazuh.common as common
from wazuh.configuration import get_ossec_conf
from wazuh.exception import WazuhException, WazuhError, WazuhInternalError
from wazuh.results import WazuhResult

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
                         extra_message="Allowed values for 'disabled' field are 'yes' and 'no'. Found: '{}'".format(config_cluster['disabled']))

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
