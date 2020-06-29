# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import random
import re
import time
from collections import OrderedDict
from datetime import datetime
from os import chmod, remove
from os.path import join
from pyexpat import ExpatError
from shutil import Error
from typing import Dict

import yaml
from xml.dom.minidom import parseString

from api import configuration
from wazuh import WazuhInternalError, WazuhError
from wazuh.core import common
from wazuh.core.cluster.utils import get_manager_status
from wazuh.core.results import WazuhResult
from wazuh.utils import load_wazuh_xml, safe_move

_re_logtest = re.compile(r"^.*(?:ERROR: |CRITICAL: )(?:\[.*\] )?(.*)$")


def status():
    """ Returns the Manager processes that are running. """

    return get_manager_status()


def get_ossec_log_fields(log):
    regex_category = re.compile(
        r"^(\d\d\d\d/\d\d/\d\d\s\d\d:\d\d:\d\d)\s(\S+)(?:\[.*)?:\s(DEBUG|INFO|CRITICAL|ERROR|WARNING):(.*)$")

    match = re.search(regex_category, log)

    if match:
        date = match.group(1)
        category = match.group(2)
        type_log = match.group(3)
        description = match.group(4)

        if "rootcheck" in category:  # Unify rootcheck category
            category = "ossec-rootcheck"

    else:
        return None

    return datetime.strptime(date, '%Y/%m/%d %H:%M:%S'), category, type_log.lower(), description


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
        except Exception as e:
            raise WazuhError(1113, str(e))

        # move temporary file to group folder
        try:
            new_conf_path = join(common.ossec_path, path)
            safe_move(tmp_file_path, new_conf_path, permissions=0o660)
        except Error:
            raise WazuhInternalError(1016)

        return WazuhResult({'message': 'File updated successfully'})

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

    return WazuhResult({'message': 'File updated successfully'})


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
    """Returns current API configuration."""
    return configuration.api_conf


def update_api_conf(new_config):
    """Update dict and subdicts without overriding unspecified keys and write it in the API.yaml file.

    Parameters
    ----------
    new_config : dict
        Dictionary with the new configuration.
    """
    if new_config:
        for key in new_config:
            if key in configuration.api_conf:
                if isinstance(configuration.api_conf[key], dict) and isinstance(new_config[key], dict):
                    configuration.api_conf[key].update(new_config[key])
                else:
                    configuration.api_conf[key] = new_config[key]

        try:
            with open(common.api_config_path, 'w+') as f:
                yaml.dump(configuration.api_conf, f)
        except IOError:
            raise WazuhInternalError(1005)
    else:
        raise WazuhError(1105)
