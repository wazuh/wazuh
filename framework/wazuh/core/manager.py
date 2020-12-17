# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import fcntl
import json
import random
import re
import socket
import time
from collections import OrderedDict
from datetime import datetime
from datetime import timezone
from os import chmod, remove
from os.path import exists, join
from pyexpat import ExpatError
from shutil import Error
from typing import Dict
from xml.dom.minidom import parseString

import yaml

from api import configuration
from wazuh import WazuhInternalError, WazuhError
from wazuh.core import common
from wazuh.core.cluster.utils import get_manager_status
from wazuh.core.results import WazuhResult
from wazuh.core.utils import load_wazuh_xml, safe_move, tail

_re_logtest = re.compile(r"^.*(?:ERROR: |CRITICAL: )(?:\[.*\] )?(.*)$")
execq_lockfile = join(common.ossec_path, "var", "run", ".api_execq_lock")


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
            tag = "ossec-rootcheck"

    else:
        return None

    return datetime.strptime(date, '%Y/%m/%d %H:%M:%S'), tag, level.lower(), description


def get_ossec_logs(limit=2000):
    """Return last <limit> lines of ossec.log file.

    Returns
    -------
        logs : list
            List of dictionaries with requested logs
    """
    logs = []

    for line in tail(common.ossec_log, limit):
        log_fields = get_ossec_log_fields(line)
        if log_fields:
            date, tag, level, description = log_fields

            # We transform local time (ossec.log) to UTC with ISO8601 maintaining time integrity
            log_line = {'timestamp': date.astimezone(timezone.utc),
                        'tag': tag, 'level': level, 'description': description}
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


def upload_xml(xml_file, path):
    """
    Upload XML files (rules and decoders)
    :param xml_file: content of the XML file
    :param path: Destination of the new XML file
    :return: Confirmation message
    """
    # -- characters are not allowed in XML comments
    xml_file = replace_in_comments(xml_file, '--', '%wildcard%')

    # path of temporary files for parsing xml input
    tmp_file_path = '{}/tmp/api_tmp_file_{}_{}.xml'.format(common.ossec_path, time.time(), random.randint(0, 1000))

    # create temporary file for parsing xml input
    try:
        with open(tmp_file_path, 'w') as tmp_file:
            # beauty xml file
            xml = parseString('<root>' + xml_file + '</root>')
            # remove first line (XML specification: <? xmlversion="1.0" ?>), <root> and </root> tags, and empty lines
            indent = '  '  # indent parameter for toprettyxml function
            pretty_xml = '\n'.join(filter(lambda x: x.strip(), xml.toprettyxml(indent=indent).split('\n')[2:-2])) + '\n'
            # revert xml.dom replacings
            # (https://github.com/python/cpython/blob/8e0418688906206fe59bd26344320c0fc026849e/Lib/xml/dom/minidom.py#L305)
            pretty_xml = pretty_xml.replace("&amp;", "&").replace("&lt;", "<").replace("&quot;", "\"", ) \
                .replace("&gt;", ">").replace('&apos;', "'")
            # delete two first spaces of each line
            final_xml = re.sub(fr'^{indent}', '', pretty_xml, flags=re.MULTILINE)
            final_xml = replace_in_comments(final_xml, '%wildcard%', '--')
            tmp_file.write(final_xml)
        chmod(tmp_file_path, 0o660)
    except IOError:
        raise WazuhInternalError(1005)
    except ExpatError:
        raise WazuhError(1113)

    try:
        # check xml format
        try:
            load_wazuh_xml(tmp_file_path)
        except WazuhError as e:
            raise e
        except Exception as e:
            raise WazuhError(1113, str(e))

        # move temporary file to group folder
        try:
            new_conf_path = join(common.ossec_path, path)
            safe_move(tmp_file_path, new_conf_path, permissions=0o660)
        except Error:
            raise WazuhInternalError(1016)

        return WazuhResult({'message': 'File was successfully updated'})

    except Exception as e:
        # remove created temporary file if an exception happens
        remove(tmp_file_path)
        raise e


def upload_list(list_file, path):
    """
    Updates CDB lists
    :param list_file: content of the list
    :param path: Destination of the new list file
    :return: Confirmation message.
    """
    # path of temporary file
    tmp_file_path = '{}/tmp/api_tmp_file_{}_{}.txt'.format(common.ossec_path, time.time(), random.randint(0, 1000))

    try:
        # create temporary file
        with open(tmp_file_path, 'w') as tmp_file:
            # write json in tmp_file_path
            for element in list_file.splitlines():
                # skip empty lines
                if not element:
                    continue
                tmp_file.write(element.strip() + '\n')
        chmod(tmp_file_path, 0o640)
    except IOError:
        raise WazuhInternalError(1005)

    # validate CDB list
    if not validate_cdb_list(tmp_file_path):
        raise WazuhError(1800)

    # move temporary file to group folder
    try:
        new_conf_path = join(common.ossec_path, path)
        safe_move(tmp_file_path, new_conf_path, permissions=0o660)
    except Error:
        raise WazuhInternalError(1016)

    return WazuhResult({'message': 'File was successfully updated'})


def validate_xml(path):
    """
    Validates a XML file
    :param path: Relative path of file from origin
    :return: True if XML is OK, False otherwise
    """
    full_path = join(common.ossec_path, path)
    try:
        with open(full_path) as f:
            parseString('<root>' + f.read() + '</root>')
    except IOError:
        raise WazuhInternalError(1005)
    except ExpatError:
        return False

    return True


def validate_cdb_list(path):
    """
    Validates a CDB list
    :param path: Relative path of file from origin
    :return: True if CDB list is OK, False otherwise
    """
    full_path = join(common.ossec_path, path)
    regex_cdb = re.compile(r'^[^:]+:[^:]*$')
    try:
        with open(full_path) as f:
            for line in f:
                # skip empty lines
                if not line.strip():
                    continue
                if not re.match(regex_cdb, line):
                    return False
    except IOError:
        raise WazuhInternalError(1005)

    return True


def validate_ossec_conf():
    """Check if Wazuh configuration is OK.

    Returns
    -------
    response : str
        Status of the configuration.
    """
    lock_file = open(execq_lockfile, 'a+')
    fcntl.lockf(lock_file, fcntl.LOCK_EX)

    try:
        # Sockets path
        api_socket_relative_path = join('queue', 'alerts', 'execa')
        api_socket_path = join(common.ossec_path, api_socket_relative_path)
        execq_socket_path = common.EXECQ
        # Message for checking Wazuh configuration
        execq_msg = 'check-manager-configuration '

        # Remove api_socket if exists
        try:
            remove(api_socket_path)
        except OSError as e:
            if exists(api_socket_path):
                extra_msg = f'Socket: WAZUH_PATH/{api_socket_relative_path}. Error: {e.strerror}'
                raise WazuhInternalError(1014, extra_message=extra_msg)

        # up API socket
        try:
            api_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            api_socket.bind(api_socket_path)
            # Timeout
            api_socket.settimeout(10)
        except OSError as e:
            extra_msg = f'Socket: WAZUH_PATH/{api_socket_relative_path}. Error: {e.strerror}'
            raise WazuhInternalError(1013, extra_message=extra_msg)

        # Connect to execq socket
        if exists(execq_socket_path):
            try:
                execq_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                execq_socket.connect(execq_socket_path)
            except OSError as e:
                extra_msg = f'Socket: WAZUH_PATH/queue/alerts/execq. Error {e.strerror}'
                raise WazuhInternalError(1013, extra_message=extra_msg)
        else:
            raise WazuhInternalError(1901)

        # Send msg to execq socket
        try:
            execq_socket.send(execq_msg.encode())
            execq_socket.close()
        except socket.error as e:
            raise WazuhInternalError(1014, extra_message=str(e))
        finally:
            execq_socket.close()

        # If api_socket receives a message, configuration is OK
        try:
            buffer = bytearray()
            # Receive data
            datagram = api_socket.recv(4096)
            buffer.extend(datagram)
        except socket.timeout as e:
            raise WazuhInternalError(1014, extra_message=str(e))
        finally:
            api_socket.close()
            # Remove api_socket
            if exists(api_socket_path):
                remove(api_socket_path)

        try:
            response = parse_execd_output(buffer.decode('utf-8').rstrip('\0'))
        except (KeyError, json.decoder.JSONDecodeError) as e:
            raise WazuhInternalError(1904, extra_message=str(e))
    finally:
        fcntl.lockf(lock_file, fcntl.LOCK_UN)
        lock_file.close()

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


def replace_in_comments(original_content, to_be_replaced, replacement):
    xml_comment = re.compile(r"(<!--(.*?)-->)", flags=re.MULTILINE | re.DOTALL)
    for comment in xml_comment.finditer(original_content):
        good_comment = comment.group(2).replace(to_be_replaced, replacement)
        original_content = original_content.replace(comment.group(2), good_comment)
    return original_content


def get_api_conf():
    """Return current API configuration."""
    return copy.deepcopy(configuration.api_conf)


def update_api_conf(new_config):
    """Update the API.yaml file.

    Parameters
    ----------
    new_config : dict
        Dictionary with the new configuration.
    """
    if new_config:
        try:
            with open(common.api_config_path, 'r') as f:
                # Avoid changing the "remote_commands" option through the Framework
                previous_config = yaml.safe_load(f)
                if 'remote_commands' in previous_config.keys():
                    new_config['remote_commands'] = previous_config['remote_commands']
            with open(common.api_config_path, 'w+') as f:
                yaml.dump(new_config, f)
        except IOError:
            raise WazuhInternalError(1005)
    else:
        raise WazuhError(1105)
