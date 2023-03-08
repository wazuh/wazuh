# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import contextlib
import datetime
import json
import os
import re
from typing import Union

from wazuh.core import common, utils
from wazuh.core import wazuh_socket
from wazuh.core.exception import WazuhError, WazuhInternalError

DAYS = "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
MONTHS = "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"


def hourly_() -> list:
    """Compute hourly averages.

    Returns
    -------
    list
        Averages and iterations.
    """
    averages = []
    interactions = 0
    for i in range(25):
        try:
            with open(f'{common.STATS_PATH}/hourly-average/{i}', mode='r') as hfile:
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


def weekly_() -> list:
    """Compute weekly averages.

    Returns
    -------
    list
        Hours and interactions for each week day.
    """
    weekly_results = []
    for i in range(7):
        hours = []
        interactions = 0
        for j in range(25):
            try:
                with open(f'{common.STATS_PATH}/weekly-average/{i}/{j}', mode='r') as wfile:
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


def totals_(date: datetime.datetime = utils.get_utc_now()) -> list:
    """Compute statistical information for the current or specified date.

    Parameters
    ----------
    date: datetime
        Date object with the date value of the stats, current date by default.

    Returns
    -------
    list
        array of dictionaries. Each dictionary represents an hour.

    Raises
    ------
    WazuhError
        Raised on `IOError`.
    """
    try:
        stat_filename = os.path.join(
            common.STATS_PATH, "totals", str(date.year), MONTHS[date.month - 1],
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


def get_daemons_stats_socket(socket: str, agents_list: Union[list[int], str] = None, last_id: int = None) -> dict:
    """Send message to Wazuh socket to get statistical information.

    Parameters
    ----------
    socket : str
        Full path of the socket to communicate with.
    agents_list : list[int], optional
        List of IDs of the agents to get the statistics from.
        If agents_list is None or empty, the global statistics are requested.
    last_id : int, optional
        Integer used to indicate the agent ID from which the daemon statistics must be returned.
        It must be used when agents_list includes the `all` keyword.

    Raises
    ------
    WazuhInternalError (1121)
        If there was an error when trying to connect to the socket.

    Returns
    -------
    dict
        Dictionary with daemon's statistical information.
    """
    # Create message
    full_message = wazuh_socket.create_wazuh_socket_message(
        origin={'module': common.origin_module.get()},
        command='getstats' if not agents_list else 'getagentsstats',
        parameters=
        {} if not agents_list else
        {'agents': agents_list} if last_id is None else
        {'agents': agents_list, 'last_id': last_id}
    )

    # Connect to socket
    try:
        s = wazuh_socket.WazuhSocketJSON(socket)
    except Exception:
        raise WazuhInternalError(1121, extra_message=socket)

    # Send message and receive socket response
    try:
        s.send(full_message)
        response = s.receive(raw=last_id is not None)
    finally:
        s.close()

    # Timestamps transformations
    with contextlib.suppress(KeyError):
        response_data = response if last_id is None else response['data']

        # timestamp field
        response_data['timestamp'] = utils.get_date_from_timestamp(response_data['timestamp'])

        # uptime field
        if not agents_list:
            response_data['uptime'] = utils.get_date_from_timestamp(response_data['uptime'])
        else:
            for agent in response_data['agents']:
                agent['uptime'] = utils.get_date_from_timestamp(agent['uptime'])

    return response


def get_daemons_stats_(filename: str) -> list:
    """Get daemons stats from an input file.

    Parameters
    ----------
    filename: str
        Full path of the file to get information.

    Returns
    -------
    list
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


def get_daemons_stats_from_socket(agent_id: str, daemon: str) -> dict:
    """Get a daemon stats from an agent or manager.

    Parameters
    ----------
    agent_id: str
        Id of the agent to get stats from.
    daemon: str
        Name of the service to get stats from.

    Returns
    -------
    dict
        Object with daemon's stats.
    """
    if not agent_id or not daemon:
        raise WazuhError(1307)

    sockets_path = os.path.join(common.WAZUH_PATH, "queue", "sockets")

    if str(agent_id).zfill(3) == '000':
        # Some daemons do not exist in agent 000
        if daemon in {'agent'}:
            raise WazuhError(1310)
        dest_socket = os.path.join(sockets_path, daemon)
        command = "getstate"
    else:
        dest_socket = common.REMOTED_SOCKET
        command = f"{str(agent_id).zfill(3)} {daemon} getstate"

    # Socket connection
    try:
        s = wazuh_socket.WazuhSocket(dest_socket)
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
        data.update((k, utils.get_utc_strptime(data[k], "%Y-%m-%d %H:%M:%S").strftime(common.DATE_FORMAT))
                    for k, v in data.items() if k in {'last_keepalive', 'last_ack'})
        return data
    except Exception:
        rec_msg = rec_msg.split(" ", 1)[1]
        raise WazuhError(1117, extra_message=rec_msg)
