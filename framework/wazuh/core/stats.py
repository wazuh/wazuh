# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import os
import re
from datetime import datetime

from wazuh.core import common
from wazuh.core.exception import WazuhError, WazuhInternalError
from wazuh.core.wazuh_socket import WazuhSocket

DAYS = "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
MONTHS = "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"


def hourly_():
    """Compute hourly averages.

    Returns
    -------
    array
        Averages and iterations.
    """
    averages = []
    interactions = 0
    for i in range(25):
        try:
            with open(f'{common.stats_path}/hourly-average/{i}', mode='r') as hfile:
                data = hfile.read()
                if i == 24:
                    interactions = int(data)
                else:
                    averages.append(int(data))
        except IOError:
            if i < 24:
                averages.append(0)
            else:
                interactions = 0

    return [{'averages': averages, 'interactions': interactions}]


def weekly_():
    """Compute weekly averages.

    Returns
    -------
    array
        Hours and interactions for each week day.
    """
    weekly_results = []
    for i in range(7):
        hours = []
        interactions = 0
        for j in range(25):
            try:
                with open(f'{common.stats_path}/weekly-average/{i}/{j}', mode='r') as wfile:
                    data = wfile.read()
                    if j == 24:
                        interactions = int(data)
                    else:
                        hours.append(int(data))
            except IOError:
                if j < 24:
                    hours.append(0)
                else:
                    interactions = 0
        weekly_results.append({DAYS[i]: {'hours': hours, 'interactions': interactions}})

    return weekly_results


def totals_(date=datetime.utcnow()):
    """Compute statistical information for the current or specified date.

    Parameters
    ----------
    date: date
        Date object with the date value of the stats, current date by default.

    Returns
    -------
    array
        array of dictionaries. Each dictionary represents an hour.

    Raises
    ------
    WazuhError
        Raised on `IOError`.
    """
    try:
        stat_filename = os.path.join(
            common.stats_path, "totals", str(date.year), MONTHS[date.month - 1],
            f"ossec-totals-{date.strftime('%d')}.log")
        with open(stat_filename, mode='r') as statsf:
            stats = statsf.readlines()
    except IOError:
        raise WazuhError(1308, extra_message=stat_filename)

    alerts = []
    affected = []
    for line in stats:
        data = line.split('-')
        if len(data) == 4:
            alerts.append({'sigid': int(data[1]), 'level': int(data[2]), 'times': int(data[3])})
        else:
            data = line.split('--')
            if len(data) != 5:
                if len(data) in (0, 1):
                    continue
                else:
                    raise WazuhInternalError(1309)
            affected.append({'hour': int(data[0]), 'alerts': alerts, 'totalAlerts': int(data[1]),
                             'events': int(data[2]), 'syscheck': int(data[3]), 'firewall': int(data[4])})
            alerts = []

    return affected


def get_daemons_stats_(filename):
    """Get daemons stats from an input file.

    Parameters
    ----------
    filename: str
        Full path of the file to get information.

    Returns
    -------
    array
        Stats of the input file.

    Raises
    ------
    WazuhError
        Raised if file does not exist.
    """
    try:
        items = {}
        with open(filename, mode='r') as f:
            daemons_data = f.read()
        try:
            kv_regex = re.compile(r'(^\w*)=(.*)', re.MULTILINE)
            for key, value in kv_regex.findall(daemons_data):
                items[key] = float(value[1:-1])
        except Exception as e:
            raise WazuhInternalError(1104, extra_message=str(e))
    except IOError:
        raise WazuhError(1308, extra_message=filename)

    return [items]


def get_daemons_stats_from_socket(agent_id, daemon):
    """Get a daemon stats from an agent or manager.

    Parameters
    ----------
    agent_id: string
        Id of the agent to get stats from.
    daemon: string
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
