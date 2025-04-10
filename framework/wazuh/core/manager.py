# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import fcntl
import json
import os
import re
import socket
import ssl
import typing
from collections import OrderedDict
from datetime import datetime
from enum import Enum
from glob import glob
from os.path import exists
from typing import Dict, Optional, Union

import certifi
import httpx
import wazuh
from wazuh import WazuhError, WazuhException, WazuhInternalError
from wazuh.core import common
from wazuh.core.configuration import get_active_configuration, get_cti_url
from wazuh.core.results import WazuhResult
from wazuh.core.utils import get_utc_now, get_utc_strptime, tail, temporary_cache
from wazuh.core.wazuh_socket import WazuhSocket, create_wazuh_socket_message

_re_logtest = re.compile(r'^.*(?:ERROR: |CRITICAL: )(?:\[.*\] )?(.*)$')

OSSEC_LOG_FIELDS = ['timestamp', 'tag', 'level', 'description']
CTI_URL = get_cti_url()
RELEASE_UPDATES_URL = os.path.join(CTI_URL, 'api', 'v1', 'ping')
ONE_DAY_SLEEP = 60 * 60 * 24
WAZUH_UID_KEY = 'wazuh-uid'
WAZUH_TAG_KEY = 'wazuh-tag'
USER_AGENT_KEY = 'user-agent'
DEFAULT_TIMEOUT = 10.0
EXECQ_LOCKFILE = common.WAZUH_RUN / '.api_execq_lock'


class LoggingFormat(Enum):
    """Logging format enumerator."""

    plain = 'plain'
    json = 'json'


def get_ossec_log_fields(log: str, log_format: LoggingFormat = LoggingFormat.plain) -> Union[tuple, None]:
    """Get ossec.log log fields.

    Parameters
    ----------
    log : str
        Log example.
    log_format : LoggingFormat
        Wazuh log format.

    Returns
    -------
    tuple or None
        Log fields: timestamp, tag, level, and description.
    """
    if log_format == LoggingFormat.plain:
        regex_category = re.compile(
            r'^(\d\d\d\d/\d\d/\d\d\s\d\d:\d\d:\d\d)\s(\S+)(?:\[.*)?:\s(DEBUG|INFO|CRITICAL|ERROR|WARNING):(.*)$'
        )

        match = re.search(regex_category, log)
        if not match:
            return None

        date = match.group(1)
        tag = match.group(2)
        level = match.group(3)
        description = match.group(4)

    elif log_format == LoggingFormat.json:
        try:
            match = json.loads(log)
        except json.decoder.JSONDecodeError:
            return None

        try:
            date = match['timestamp']
            tag = match['tag']
            level = match['level']
            description = match['description']
        except KeyError:
            return None
    else:
        return None

    if 'rootcheck' in tag:  # Unify rootcheck category
        tag = 'wazuh-rootcheck'

    return get_utc_strptime(date, '%Y/%m/%d %H:%M:%S'), tag, level.lower(), description


def get_wazuh_active_logging_format() -> LoggingFormat:
    """Obtain the Wazuh active logging format.

    Returns
    -------
    LoggingFormat
        Wazuh active log format. Can either be `plain` or `json`. If it has both types, `plain` will be returned.
    """
    active_logging = get_active_configuration(component='com', configuration='logging')['logging']
    return LoggingFormat.plain if active_logging['plain'] == 'yes' else LoggingFormat.json


def get_ossec_logs(limit: int = 2000) -> list:
    """Return last <limit> lines of ossec.log file.

    Parameters
    ----------
    limit : int
        Number of lines to return. Default: 2000

    Returns
    -------
    list
        List of dictionaries with requested logs.
    """
    logs = []

    log_format = get_wazuh_active_logging_format()
    if log_format == LoggingFormat.plain and exists(common.WAZUH_LOG):
        wazuh_log_content = tail(common.WAZUH_LOG, limit)
    elif log_format == LoggingFormat.json and exists(common.WAZUH_LOG_JSON):
        wazuh_log_content = tail(common.WAZUH_LOG_JSON, limit)
    else:
        raise WazuhInternalError(1000)

    for line in wazuh_log_content:
        log_fields = get_ossec_log_fields(line, log_format=log_format)
        if log_fields:
            date, tag, level, description = log_fields

            # We transform local time (ossec.log) to UTC with ISO8601 maintaining time integrity
            log_line = {
                'timestamp': date.strftime(common.DATE_FORMAT),
                'tag': tag,
                'level': level,
                'description': description,
            }
            logs.append(log_line)

    return logs


def get_logs_summary(limit: int = 2000) -> dict:
    """Get the number of alerts of each tag.

    Parameters
    ----------
    limit : int
        Number of lines to return. Default: 2000

    Returns
    -------
    dict
        Number of logs for every tag.
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


def validate_ossec_conf() -> str:
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
    """Parse output from execd socket to fetch log message and remove log date, log daemon, log level, etc.

    Parameters
    ----------
    output : str
        Raw output from execd.

    Returns
    -------
    dict
        Cleaned log message in a dictionary structure.
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


def _get_ssl_context() -> ssl.SSLContext:
    """Return a default ssl context."""
    return ssl.create_default_context(cafile=certifi.where())


def get_update_information_template(
    uuid: str,
    update_check: bool,
    current_version: str = f'v{wazuh.__version__}',
    last_check_date: Optional[datetime] = None,
) -> dict:
    """Build and return a template for the update_information dict.

    Parameters
    ----------
    uuid : str
        Wazuh UID to include in the result.
    update_check : bool
        Indicates if the check is enabled or not.
    current_version : str, optional
        Indicates the current version of Wazuh, by default wazuh.__version__.
    last_check_date : Optional[datetime], optional
        Indicates the datetime of the last check, by default None.

    Returns
    -------
    dict
        Template with the given data.
    """
    return {
        'uuid': uuid,
        'last_check_date': last_check_date if last_check_date is not None else '',
        'current_version': current_version,
        'update_check': update_check,
        'last_available_major': {},
        'last_available_minor': {},
        'last_available_patch': {},
    }


async def query_update_check_service(installation_uid: str) -> dict:
    """Make a query to the update check service and retrieve updates information.

    Parameters
    ----------
    installation_uid : str
        Wazuh UID to include in the query.

    Returns
    -------
    update_information : dict
        Updates information.
    """
    current_version = f'v{wazuh.__version__}'
    headers = {
        WAZUH_UID_KEY: installation_uid,
        WAZUH_TAG_KEY: current_version,
        USER_AGENT_KEY: f'Wazuh UpdateCheckService/{current_version}',
    }

    update_information = get_update_information_template(
        uuid=installation_uid, update_check=True, current_version=current_version, last_check_date=get_utc_now()
    )

    async with httpx.AsyncClient(verify=_get_ssl_context(), timeout=httpx.Timeout(DEFAULT_TIMEOUT)) as client:
        try:
            response = await client.get(RELEASE_UPDATES_URL, headers=headers, follow_redirects=True)
            response_data = response.json()

            update_information['status_code'] = response.status_code

            if response.status_code == 200:
                if len(response_data['data']['major']):
                    update_information['last_available_major'].update(**response_data['data']['major'][-1])
                if len(response_data['data']['minor']):
                    update_information['last_available_minor'].update(**response_data['data']['minor'][-1])
                if len(response_data['data']['patch']):
                    update_information['last_available_patch'].update(**response_data['data']['patch'][-1])
            else:
                update_information['message'] = response_data['errors']['detail']
        except httpx.RequestError as err:
            update_information.update({'message': str(err), 'status_code': 500})
        except Exception as err:
            update_information.update({'message': str(err), 'status_code': 500})

    return update_information


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
    lock_file = open(EXECQ_LOCKFILE, 'a+')
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
