# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from io import StringIO

from wazuh.core import common
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.exception import WazuhError, WazuhInternalError
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import expose_resources

try:
    import configparser

    unicode = str
except ImportError:
    import ConfigParser as configparser

DAYS = "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
MONTHS = "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
cluster_enabled = not read_cluster_config()['disabled']
node_id = get_node().get('node') if cluster_enabled else None


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def totals(date):
    """
    Returns the totals file.
    :param date: date object with the date value of the stats
    :return: Array of dictionaries. Each dictionary represents an hour.
    """

    stat_filename = ""
    try:
        stat_filename = os.path.join(
            common.stats_path, "totals", str(date.year), MONTHS[date.month - 1],
            f"ossec-totals-{date.strftime('%d')}.log")
        stats = open(stat_filename, 'r')
    except IOError:
        raise WazuhError(1308, extra_message=stat_filename)

    result = AffectedItemsWazuhResult(all_msg='Statistical information for each node was successfully read',
                                      some_msg='Could not read statistical information for some nodes',
                                      none_msg='Could not read statistical information for any node'
                                      )
    alerts = []

    for line in stats:
        data = line.split('-')

        if len(data) == 4:
            sigid = int(data[1])
            level = int(data[2])
            times = int(data[3])

            alert = {'sigid': sigid, 'level': level, 'times': times}
            alerts.append(alert)
        else:
            data = line.split('--')

            if len(data) != 5:
                if len(data) in (0, 1):
                    continue
                else:
                    result.add_failed_item(id_=node_id, error=WazuhInternalError(1309))
                    return result

            hour = int(data[0])
            total_alerts = int(data[1])
            events = int(data[2])
            syscheck = int(data[3])
            firewall = int(data[4])

            result.affected_items.append(
                {'hour': hour, 'alerts': alerts, 'totalAlerts': total_alerts, 'events': events, 'syscheck': syscheck,
                 'firewall': firewall})
            alerts = []

    result.total_affected_items = len(result.affected_items)
    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def hourly():
    """
    Returns the hourly averages.
    :return: Dictionary: averages and interactions.
    """

    averages = []
    interactions = 0

    # What's the 24 for?
    for i in range(25):
        try:
            hfile = open(common.stats_path + '/hourly-average/' + str(i))
            data = hfile.read()

            if i == 24:
                interactions = int(data)
            else:
                averages.append(int(data))

            hfile.close()
        except IOError:
            if i < 24:
                averages.append(0)

    result = AffectedItemsWazuhResult(all_msg='Statistical information per hour for each node was successfully read',
                                      some_msg='Could not read statistical information per hour for some nodes',
                                      none_msg='Could not read statistical information per hour for any node'
                                      )
    result.affected_items.append({'averages': averages, 'interactions': interactions})
    result.total_affected_items = len(result.affected_items)
    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def weekly():
    """
    Returns the weekly averages.
    :return: A dictionary for each week day.
    """
    result = AffectedItemsWazuhResult(all_msg='Statistical information per week for each node was successfully read',
                                      some_msg='Could not read statistical information per week for some nodes',
                                      none_msg='Could not read statistical information per week for any node'
                                      )
    # 0..6 => Sunday..Saturday
    for i in range(7):
        hours = []
        interactions = 0

        for j in range(25):
            try:
                wfile = open(common.stats_path + '/weekly-average/' + str(i) + '/' + str(j))
                data = wfile.read()

                if j == 24:
                    interactions = int(data)
                else:
                    hours.append(int(data))

                wfile.close()
            except IOError:
                if i < 24:
                    hours.append(0)

        result.affected_items.append({DAYS[i]: {'hours': hours, 'interactions': interactions}})

    result.total_affected_items = len(result.affected_items)
    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def get_daemons_stats(filename):
    """Returns the stats of an input file.

    :param filename: Full path of the file to get information.
    :return: A dictionary with the stats of the input file.
    """
    result = AffectedItemsWazuhResult(
        all_msg='Statistical information for each node was successfully read',
        some_msg='Could not read statistical information for some nodes',
        none_msg='Could not read statistical information for any node'
        )
    try:

        with open(filename, 'r') as f:
            input_file = unicode("[root]\n" + f.read())

        fp = StringIO(input_file)
        config = configparser.RawConfigParser()
        config.read_file(fp)
        items = dict(config.items("root"))

        try:
            for key, value in items.items():
                items[key] = float(value[1:-1])  # Delete extra quotation marks
            result.affected_items.append(items)
        except Exception as e:
            return WazuhInternalError(1104, extra_message=str(e))

    except IOError:
        raise WazuhError(1308, extra_message=filename)

    result.total_affected_items = len(result.affected_items)
    return result
