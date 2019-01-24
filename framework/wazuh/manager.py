#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import execute, previous_month, cut_array, sort_array, search_array, tail
from wazuh.exception import WazuhException
from wazuh.utils import load_wazuh_xml
from wazuh import common
from datetime import datetime
import time
from os.path import exists
from glob import glob
import re
import hashlib
from xml.dom.minidom import parseString
from shutil import move
from os import remove
import random


def status():
    """
    Returns the Manager processes that are running.
    :return: Array of dictionaries (keys: status, daemon).
    """

    processes = ['ossec-monitord', 'ossec-logcollector', 'ossec-remoted',
                 'ossec-syscheckd', 'ossec-analysisd', 'ossec-maild',
                 'ossec-execd', 'wazuh-modulesd', 'ossec-authd',
                 'wazuh-clusterd']

    data = {}
    for process in processes:
        data[process] = 'stopped'

        process_pid_files = glob("{0}/var/run/{1}-*.pid".format(common.ossec_path, process))

        for pid_file in process_pid_files:
            m = re.match(r'.+\-(\d+)\.pid$', pid_file)

            pid = "NA"
            if m and m.group(1):
                pid = m.group(1)

            if exists(pid_file) and exists('/proc/{0}'.format(pid)):
                data[process] = 'running'
                break

    return data

def __get_ossec_log_fields(log):
    regex_category = re.compile("^(\d\d\d\d/\d\d/\d\d\s\d\d:\d\d:\d\d)\s(\S+):\s(\S+):\s(.*)$")

    match = re.search(regex_category, log)

    if match:
        date        = match.group(1)
        category    = match.group(2)
        type_log    = match.group(3)
        description = match.group(4)

        if "rootcheck" in category:  # Unify rootcheck category
            category = "ossec-rootcheck"

        if "(" in category:  # Remove ()
            category = re.sub("\(\d\d\d\d\)", "", category)
    else:
        return None

    return datetime.strptime(date, '%Y/%m/%d %H:%M:%S'), category, type_log.lower(), description


def ossec_log(type_log='all', category='all', months=3, offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Gets logs from ossec.log.

    :param type_log: Filters by log type: all, error or info.
    :param category: Filters by log category (i.e. ossec-remoted).
    :param months: Returns logs of the last n months. By default is 3 months.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    logs = []

    first_date = previous_month(months)
    statfs_error = "ERROR: statfs('******') produced error: No such file or directory"

    for line in tail(common.ossec_log, 2000):
        log_fields = __get_ossec_log_fields(line)
        if log_fields:
            log_date, log_category, level, description = log_fields

            if log_date < first_date:
                continue

            if category != 'all':
                if log_category:
                    if log_category != category:
                        continue
                else:
                    continue

            log_line = {'timestamp': str(log_date), 'tag': log_category, 'level': level, 'description': description}
            if type_log == 'all':
                logs.append(log_line)
            elif type_log.lower() == level.lower():
                if "ERROR: statfs(" in line:
                    if statfs_error in logs:
                        continue
                    else:
                        logs.append(statfs_error)
                else:
                    logs.append(log_line)
            else:
                continue
        else:
            if logs != []:
                logs[-1]['description'] += "\n" + line

    if search:
        logs = search_array(logs, search['value'], search['negation'])

    if sort:
        if sort['fields']:
            logs = sort_array(logs, order=sort['order'], sort_by=sort['fields'])
        else:
            logs = sort_array(logs, order=sort['order'], sort_by=['timestamp'])
    else:
        logs = sort_array(logs, order='desc', sort_by=['timestamp'])

    return {'items': cut_array(logs, offset, limit), 'totalItems': len(logs)}


def ossec_log_summary(months=3):
    """
    Summary of ossec.log.

    :param months: Check logs of the last n months. By default is 3 months.
    :return: Dictionary by categories.
    """
    categories = {}

    first_date = previous_month(months)

    with open(common.ossec_log) as f:
        lines_count = 0
        for line in f:
            if lines_count > 50000:
                break
            lines_count = lines_count + 1

            line = __get_ossec_log_fields(line)

            # multine logs
            if line is None:
                continue

            log_date, category, log_type, _, = line

            if log_date < first_date:
                break

            if category:
                if category in categories:
                    categories[category]['all'] += 1
                else:
                    categories[category] = {'all': 1, 'info': 0, 'error': 0, 'critical': 0, 'warning': 0, 'debug': 0}
                categories[category][log_type] += 1
            else:
                continue
    return categories


def upload_file(xml_file, path):
    """
    Updates a group file

    :param xml_file: File contents in string
    :param file_name: File name to update
    :return: Confirmation message in string
    """
    with open(xml_file) as f:
        xml_file_data = f.read()

    if len(xml_file_data) == 0:
        raise WazuhException(1112)

    return upload_xml(xml_file_data, path)


def upload_xml(xml_file, path):
    """
    Updates local rules
    :param group_id: Group to update
    :param xml_file: File contents of the new rules.
    :return: Confirmation message.
    """

    # path of temporary files for parsing xml input
    tmp_file_path = '{}/tmp/api_tmp_file_{}_{}.xml'.format(common.ossec_path, time.time(), random.randint(0, 1000))

    # create temporary file for parsing xml input
    try:
        with open(tmp_file_path, 'w') as tmp_file:
            # beauty xml file
            xml = parseString('<root>' +  xml_file + '</root>')
            # remove first line (XML specification: <? xmlversion="1.0" ?>), <root> and </root> tags, and empty lines
            pretty_xml = '\n'.join(filter(lambda x: x.strip(), xml.toprettyxml(indent='  ').split('\n')[2:-2])) + '\n'
            # revert xml.dom replacings
            # (https://github.com/python/cpython/blob/8e0418688906206fe59bd26344320c0fc026849e/Lib/xml/dom/minidom.py#L305)
            pretty_xml = pretty_xml.replace("&amp;", "&").replace("&lt;", "<").replace("&quot;", "\"",)\
                                   .replace("&gt;", ">").replace('&apos', "'")
            tmp_file.write(pretty_xml)
    except Exception as e:
        raise WazuhException(1113, str(e))

    try:
        # check xml format
        try:
            load_wazuh_xml(tmp_file_path)
        except Exception as e:
            raise WazuhException(1113, str(e))

        # move temporary file to group folder
        try:
            new_conf_path = "{}/{}".format(common.ossec_path, path)
            move(tmp_file_path, new_conf_path)
        except Exception as e:
            raise WazuhException(1017, str(e))

        return 'Local rules were updated successfully' # may be a decoder
    except Exception as e:
        # remove created temporary file
        remove(tmp_file_path)
        raise e


def get_file(path, output_format):
    """
    Returns a file as dictionary.
    :param path: Path of file from origin
    :param file_name: File name to update
    :return: file as dictionary or XML string.
    """

    file_path = common.ossec_path + path
    output = {}

    if output_format == 'json':
        with open(file_path) as f:
            for line in f:
                if '\n' in line:
                    line = line.replace('\n', '')
                key = line.split(':')[0]
                value = line.split(':')[1]
                output[key] = value
    elif output_format == 'xml':
        with open(file_path) as f:
            output = f.read()

    return output
