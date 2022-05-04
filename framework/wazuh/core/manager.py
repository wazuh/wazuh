# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import json
import re
import socket
from collections import OrderedDict
from os.path import exists
from typing import Dict

from api import configuration
from wazuh import WazuhInternalError, WazuhError, WazuhException
from wazuh.core import common
from wazuh.core.cluster import cluster
from wazuh.core.cluster.utils import get_manager_status
from wazuh.core.utils import tail, get_utc_strptime
from wazuh.core.wazuh_socket import WazuhSocket

_re_logtest = re.compile(r"^.*(?:ERROR: |CRITICAL: )(?:\[.*] )?(.*)$")


def status():
    """ Returns the Manager processes that are running. """

    return get_manager_status()


def get_ossec_log_fields(log):
    regex_category = re.compile(
        r"^(\d\d\d\d/\d\d/\d\d\s\d\d:\d\d:\d\d)\s(\S+)(?:\[.*)?:\s(DEBUG|INFO|CRITICAL|ERROR|WARNING):(.*)$")

    match = re.search(regex_category, log)

    if match:
        date = match.group(1)
        tag = match.group(2)
        level = match.group(3)
        description = match.group(4)

        if "rootcheck" in tag:  # Unify rootcheck category
            tag = "wazuh-rootcheck"

    else:
        return None

    return get_utc_strptime(date, '%Y/%m/%d %H:%M:%S'), tag, level.lower(), description


def get_ossec_logs(limit=2000):
    """Return last <limit> lines of ossec.log file.

    Returns
    -------
        logs : list
            List of dictionaries with requested logs
    """
    logs = []

    for line in tail(common.OSSEC_LOG, limit):
        log_fields = get_ossec_log_fields(line)
        if log_fields:
            date, tag, level, description = log_fields

            # We transform local time (ossec.log) to UTC with ISO8601 maintaining time integrity
            log_line = {'timestamp': date.strftime(common.DATE_FORMAT), 'tag': tag,
                        'level': level, 'description': description}
            logs.append(log_line)

    return logs


def get_logs_summary(limit=2000):
    """Get the number of alerts of each tag.

    Parameters
    ----------
    limit : int
        Number of lines to process.

    Returns
    -------
    tags : dict
        Number of logs for every tag
    """
    tags = dict()
    logs = get_ossec_logs(limit)

    for log in logs:
        if log['tag'] in tags:
            tags[log['tag']]['all'] += 1
        else:
            tags[log['tag']] = {'all': 1, 'info': 0, 'error': 0, 'critical': 0, 'warning': 0, 'debug': 0}
        tags[log['tag']][log['level']] += 1

    return tags


def validate_ossec_conf():
    """Check if Wazuh configuration is OK.

    Raises
    ------
    WazuhInternalError(1014)
        If there is a socket communication error.
    WazuhInternalError(1013)
        If it is unable to connect to socket.
    WazuhInternalError(1901)
        If 'execq' socket cannot be created.
    WazuhInternalError(1904)
        If there is bad data received from 'execq'.

    Returns
    -------
    str
        Status of the configuration.
    """

    # Socket path
    wcom_socket_path = common.WCOM_SOCKET
    # Message for checking Wazuh configuration
    wcom_msg = common.CHECK_CONFIG_COMMAND

    # Connect to wcom socket
    if exists(wcom_socket_path):
        try:
            wcom_socket = WazuhSocket(wcom_socket_path)
        except WazuhException as e:
            if e.code == 1017:
                raise WazuhError(1017, extra_message=e.message)
            else:
                extra_msg = f'Socket: WAZUH_PATH/queue/sockets/com. Error {e.message}'
                raise WazuhInternalError(1013, extra_message=extra_msg)
    else:
        raise WazuhInternalError(1901)

    # Send msg to wcom socket
    try:
        wcom_socket.send(wcom_msg.encode())

        buffer = bytearray()
        datagram = wcom_socket.receive()
        buffer.extend(datagram)

    except (socket.error, socket.timeout) as e:
        raise WazuhInternalError(1014, extra_message=str(e))
    finally:
        wcom_socket.close()

    try:
        response = parse_execd_output(buffer.decode('utf-8').rstrip('\0'))
    except (KeyError, json.decoder.JSONDecodeError) as e:
        raise WazuhInternalError(1904, extra_message=str(e))

    return response


def parse_execd_output(output: str) -> Dict:
    """
    Parses output from execd socket to fetch log message and remove log date, log daemon, log level, etc.
    :param output: Raw output from execd
    :return: Cleaned log message in a dictionary structure
    """
    json_output = json.loads(output)
    error_flag = json_output['error']
    if error_flag != 0:
        errors = []
        log_lines = json_output['message'].splitlines(keepends=False)
        for line in log_lines:
            match = _re_logtest.match(line)
            if match:
                errors.append(match.group(1))
        errors = list(OrderedDict.fromkeys(errors))
        raise WazuhError(1908, extra_message=', '.join(errors))
    else:
        response = {'status': 'OK'}

    return response


def get_api_conf():
    """Return current API configuration."""
    return copy.deepcopy(configuration.api_conf)


def check_wazuh_status(required_daemons: set):
    """There are some services that are required for wazuh to correctly process API requests. If any of those services
    is not running, the API must raise an exception indicating that:
        * It's not ready yet to process requests if services are restarting
        * There's an error in any of those services that must be addressed before using the API if any service is
          in failed status.
        * Wazuh must be started before using the API is the services are stopped.

    Parameters
    ----------
    required_daemons: set of WazuhDaemons
        Set of instances of the class `WazuhDaemons`

    Raises
    ------
    WazuhError(1017)
        If any of the `required_daemons` is not running.
    """
    status = get_manager_status()

    not_ready_daemons = {k.value: status[k.value] for k in required_daemons if status[k.value] in ('failed',
                                                                                                   'restarting',
                                                                                                   'stopped')}

    if not_ready_daemons:
        extra_info = {
            'node_name': cluster.get_node().get('node', 'UNKNOWN NODE'),
            'not_ready_daemons': ', '.join([f'{key}->{value}' for key, value in not_ready_daemons.items()])
        }
        raise WazuhError(1017, extra_message=extra_info)
