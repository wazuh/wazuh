#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import execute, previous_month, cut_array, sort_array, search_array, tail
from wazuh import common
from datetime import datetime
from os.path import exists
from glob import glob
import re


def status():
    """
    Returns the Manager processes that are running.
    :return: Array of dictionaries (keys: status, daemon).
    """

    processes = ['ossec-monitord', 'ossec-logcollector', 'ossec-remoted', 'ossec-syscheckd', 'ossec-analysisd', 'ossec-maild', 'ossec-execd', 'wazuh-modulesd', 'ossec-authd']

    data = {}
    for process in processes:
        process_path = glob("{0}/var/run/{1}-*.pid".format(common.ossec_path, process))

        if process_path and exists(process_path[0]):
            data[process] = 'running'
        else:
            data[process] = 'stopped'

    return data

def __get_ossec_log_category(log):
    regex_category = re.compile("^\d\d\d\d/\d\d/\d\d\s\d\d:\d\d:\d\d\s(\S+):\s")

    match = re.search(regex_category, log)

    if match:
        category = match.group(1)

        if "rootcheck" in category:  # Unify rootcheck category
            category = "ossec-rootcheck"

        if "(" in category:  # Remove ()
            category = re.sub("\(\d\d\d\d\)", "", category)
    else:
        return None

    return category


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
        try:
            log_date = datetime.strptime(line[:10], '%Y/%m/%d')
        except ValueError:
            continue

        if log_date < first_date:
            continue

        if category != 'all':
            log_category = __get_ossec_log_category(line)

            if log_category:
                if log_category != category:
                    continue
            else:
                continue

        line = line.replace('\n', '')
        if type_log == 'all':
            logs.append(line)
        elif type_log == 'error' and "error:" in line.lower():
            if "ERROR: statfs(" in line:
                if statfs_error in logs:
                    continue
                else:
                    logs.append(statfs_error)
            else:
                logs.append(line)
        elif type_log == 'info' and "error:" not in line.lower():
            logs.append(line)

    if search:
        logs = search_array(logs, search['value'], search['negation'])

    if sort:
        logs = sort_array(logs, order=sort['order'])
    else:
        logs = sort_array(logs, order='desc')

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
            try:
                log_date = datetime.strptime(line[:10], '%Y/%m/%d')
            except ValueError:
                continue

            if log_date < first_date:
                break

            category = __get_ossec_log_category(line)
            if category:
                if category in categories:
                    categories[category]['all'] += 1
                else:
                    categories[category] = {'all': 1, 'info': 0, 'error': 0}

                if "error" in line.lower():
                    categories[category]['error'] += 1
                else:
                    categories[category]['info'] += 1
            else:
                continue
    return categories
