# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import configparser
import json
import os
from datetime import datetime
from io import StringIO

from wazuh.core import agent, common
from wazuh.core.exception import (WazuhError, WazuhException,
                                  WazuhInternalError, WazuhResourceNotFound)
from wazuh.core.wazuh_socket import WazuhSocket

DAYS = "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
MONTHS = "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"


def hourly_():
    """Compute hourly averages

    Returns
    -------
    array
        averages and iterations
    """
    averages = []
    interactions = 0
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

    return [{'averages': averages, 'interactions': interactions}]


def weekly_():
    """Compute weekly averages

    Returns
    -------
    array
        hours and interactions for each week day
    """
    weekly_results = []
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
        weekly_results.append({DAYS[i]: {'hours': hours, 'interactions': interactions}})

    return weekly_results


def totals_(date):
    """Statistical information for the current or specified date

    Parameters
    ----------
    date : date
        date object with the date value of the stats

    Returns
    -------
    tuple
        failed: boolean that represents if data parsing failed
        affected: array of dictionaries. Each dictionary represents an hour

    Raises
    ------
    WazuhError
        raised on IOError
    """
    try:
        stat_filename = os.path.join(
            common.stats_path, "totals", str(date.year), MONTHS[date.month - 1],
            f"ossec-totals-{date.strftime('%d')}.log")
        stats = open(stat_filename, 'r')
    except IOError:
        raise WazuhError(1308, extra_message=stat_filename)
    alerts = []
    affected = []
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
                    return True, affected
            hour = int(data[0])
            total_alerts = int(data[1])
            events = int(data[2])
            syscheck = int(data[3])
            firewall = int(data[4])
            affected.append(
                {'hour': hour,
                 'alerts': alerts,
                 'totalAlerts': total_alerts,
                 'events': events,
                 'syscheck': syscheck,
                 'firewall': firewall
                 })
            alerts = []

    return False, affected


def get_daemons_stats_(filename):
    """Get daemons stats from an input file

    Parameters
    ----------
    filename : str
        full path of the file to get information

    Returns
    -------
    array
        stats of the input file

    Raises
    ------
    WazuhError
        raised if file does not exist
    """
    try:
        with open(filename, mode='r') as f:
            input_file = str("[root]\n" + f.read())
        fp = StringIO(input_file)
        config = configparser.RawConfigParser()
        config.read_file(fp)
        items = dict(config.items("root"))
        try:
            for key, value in items.items():
                items[key] = float(value[1:-1])
        except Exception as e:
            return WazuhInternalError(1104, extra_message=str(e))
    except IOError:
        raise WazuhError(1308, extra_message=filename)

    return [items]


def get_agents_component_stats_json_(agent_list, component):
    """Get statistics of an agent's component

    Parameters
    ----------
    agent_list : list, optional
        list of agents ID's, by default None
    component : str, optional
        name of the component to get stats from, by default None

    Returns
    -------
    tuple
        failed: array of failed agent's information and related wazuh error
        affected: array of agent's statistics

    Raises
    ------
    WazuhResourceNotFound
        raised if agent does not exist.
    """
    failed = []
    affected = []
    system_agents = agent.get_agents_info()
    for agent_id in agent_list:
        try:
            if agent_id not in system_agents:
                raise WazuhResourceNotFound(1701)
            affected.append(agent.Agent(agent_id).get_stats(component=component))
        except WazuhException as e:
            failed.append((agent_id, e))

    return failed, affected


def get_daemons_stats_from_socket(agent_id, daemon):
    """Get a daemon stats from an agent or manager.

    Parameters
    ----------
    agent_id : string
        Id of the agent to get stats from.
    daemon : string
        Name of the service to get stats from.

    Returns
    -------
    Dict
        Object with daemon's stats.
    """
    if not agent_id or not daemon:
        raise WazuhError(1307)

    sockets_path = os.path.join(common.wazuh_path, "queue", "sockets")

    if str(agent_id).zfill(3) == '000':
        # Some daemons do not exist in agent 000
        if daemon in {'agent'}:
            raise WazuhError(1310)
        dest_socket = os.path.join(sockets_path, daemon)
        command = "getstate"
    else:
        dest_socket = os.path.join(sockets_path, "request")
        command = f"{str(agent_id).zfill(3)} {daemon} getstate"

    # Socket connection
    try:
        s = WazuhSocket(dest_socket)
    except Exception:
        raise WazuhInternalError(1121)

    # Send message
    s.send(command.encode())

    # Receive response
    try:
        rec_msg = s.receive().decode()
    except ValueError:
        raise WazuhInternalError(1118, extra_message="Data could not be received")

    s.close()

    # Format response
    try:
        data = json.loads(rec_msg)['data']
        data.update((k, datetime.strptime(data[k], "%Y-%m-%d %H:%M:%S").strftime(common.date_format))
                    for k, v in data.items() if k in {'last_keepalive', 'last_ack'})
        return data
    except Exception:
        rec_msg = rec_msg.split(" ", 1)[1]
        raise WazuhError(1117, extra_message=rec_msg)
