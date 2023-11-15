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
from wazuh.core.exception import WazuhError, WazuhInternalError, WazuhException

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


async def get_daemons_stats_socket(socket: str,
                                   agents_list: Union[list[int], str] = None,
                                   last_id: int = None) -> dict:
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
        s = wazuh_socket.WazuhAsyncSocketJSON()
        await s.connect(socket)
    except Exception as exc:
        raise WazuhInternalError(1121, extra_message=socket) from exc

    # Send message and receive socket response
    try:
        await s.send(full_message)
        response = await (s.receive_json() if last_id is None else s.receive())
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
    filename : str
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


def is_agent_a_manager(agent_id: Union[str, int]) -> bool:
    """Check if the given agent ID corresponds to a manager agent.

    Parameters
    ----------
    agent_id : Union[str, int]
        The ID of the agent to check, which can be either a string or an integer.

    Returns
    -------
    bool
        True if the agent is a manager (ID is '000'), False otherwise.
    """
    return str(agent_id).zfill(3) == '000'


def get_stats_socket_path(agent_id: Union[str, int], daemon: str) -> str:
    """Get the socket path for retrieving statistics based on agent type.

    Parameters
    ----------
    agent_id : Union[str, int]
        The ID of the agent, which can be either a string or an integer.
    daemon : str
        The name of the daemon.

    Returns
    -------
    str
        The path to the socket for communication.
    """
    if is_agent_a_manager(agent_id):
        return os.path.join(common.WAZUH_PATH, "queue", "sockets", daemon)
    else:
        return common.REMOTED_SOCKET


def create_stats_command(agent_id: Union[str, int], daemon: str, next_page: bool = False) -> str:
    """Create a command to retrieve statistics based on agent type.

    Parameters
    ----------
    agent_id: Union[str, int]
        The ID of the agent, which can be either a string or an integer.
    daemon: str
        The name of the daemon.
    next_page: bool
        If True, request the next page of the response.

    Returns
    -------
    str
        The command to retrieve statistics.
    """
    command = None
    if is_agent_a_manager(agent_id):
        command = "getstate"
    else:
        command = f"{str(agent_id).zfill(3)} {daemon} getstate"

    if next_page:
        command += " next"

    return command


def check_if_daemon_exists_in_agent(agent_id: Union[str, int], daemon: str) -> bool:
    """Check if a daemon exists for a given agent.

    Parameters
    ----------
    agent_id : Union[str, int]
        The ID of the agent, which can be either a string or an integer.
    daemon : str
        The name of the daemon.

    Returns
    -------
    bool
        True if the daemon exists for the agent, False otherwise.
    """
    # Some daemons do not exist in agent 000
    return not (is_agent_a_manager(agent_id) and daemon in {'agent'})


def send_command_to_socket(dest_socket: str, command: str) -> dict:
    """Send a command to a socket
    Parameters
    ----------
    dest_socket : str
        The destination socket path.
    command : str
        The command to send to the socket

    Returns
    -------
    dict
        Response from the socket

    """
    try:
        s = wazuh_socket.WazuhSocket(dest_socket)
    except WazuhException:
        # Error connecting to socket
        raise WazuhInternalError(1121)

    try:
        s.send(command.encode())
        try:
            return s.receive().decode()
        except ValueError:
            raise WazuhInternalError(1118, extra_message="Data could not be received")
    finally:
        s.close()


def get_daemons_stats_from_socket(agent_id: str, daemon: str) -> dict:
    """Get a daemon stats from an agent or manager.

    Parameters
    ----------
    agent_id : str
        Id of the agent to get stats from.
    daemon : str
        Name of the service to get stats from.

    Returns
    -------
    dict
        Object with daemon's stats.
    """
    if not agent_id or not daemon:
        raise WazuhError(1307)

    if not check_if_daemon_exists_in_agent(agent_id=agent_id, daemon=daemon):
        raise WazuhError(1310)

    dest_socket = get_stats_socket_path(agent_id=agent_id, daemon=daemon)
    command = create_stats_command(agent_id=agent_id, daemon=daemon)

    socket_msg = send_command_to_socket(dest_socket, command)
    socket_response = json.loads(socket_msg)

    # Handle error
    if socket_response.get('error', 0) != 0:
        rec_msg = socket_response.get('message', "")
        raise WazuhError(1117, extra_message=rec_msg)

    if 'global' in socket_response['data'] and 'interval' in socket_response['data']:
        global_data = socket_response['data'].get('global', {})
        interval_data = socket_response['data'].get('interval', {})
        data = {'global': PaginatedDataHandler(), 'interval': PaginatedDataHandler()}

        data['global'].set_data(global_data)
        data['interval'].set_data(interval_data)

        while socket_response.get('remaining', False):
            last_json_updated = socket_response.get('json_updated', False)
            command = create_stats_command(agent_id=agent_id, daemon=daemon,
                                           next_page=not last_json_updated)
            rec_msg = send_command_to_socket(dest_socket, command)
            socket_response = json.loads(rec_msg)

            global_data = socket_response['data'].get('global', {})
            interval_data = socket_response['data'].get('interval', {})

            if last_json_updated:
                data = {'global': PaginatedDataHandler(), 'interval': PaginatedDataHandler()}

                data['global'].set_data(global_data)
                data['interval'].set_data(interval_data)
            else:
                if data['global'].is_empty():
                    data['global'].set_data(global_data)
                else:
                    data['global'].update_data(global_data)

                if data['interval'].is_empty():
                    data['interval'].set_data(interval_data)
                else:
                    data['interval'].update_data(interval_data)

        return {'global': data['global'].to_dict(), 'interval': data['interval'].to_dict()}
    else:
        data = socket_response['data']
        data.update((k, utils.get_utc_strptime(data[k], "%Y-%m-%d %H:%M:%S").strftime(common.DATE_FORMAT))
                    for k, v in data.items() if k in {'last_keepalive', 'last_ack'})
        return data


class PaginatedDataHandler:
    """Class for handling paginated data.

    Attributes
    ----------
    _internal_data : dict
        Internal data storage.

    Methods
    -------
    is_empty()
        Check if internal data is empty.
    set_data(data)
        Set internal data with the provided data.
    update_data(data)
        Update internal data with the provided data.
    to_dict()
        Return the internal data as a dictionary.

    """

    def __init__(self):
        """Initialize an instance of PaginationData."""
        self._internal_data = {}

    def is_empty(self):
        """Check if internal data is empty.

        Returns
        -------
        bool
            True if internal data is empty, False otherwise.

        """
        return len(self._internal_data) == 0

    def set_data(self, data):
        """Set internal data with the provided data.

        Parameters
        ----------
        data : dict
            Data to set.

        """
        if data:
            self._internal_data = data
            self._internal_data['start'] = utils.get_utc_strptime(data['start'], "%Y-%m-%d %H:%M:%S").strftime(common.DATE_FORMAT)
            self._internal_data['end'] = utils.get_utc_strptime(data['end'], "%Y-%m-%d %H:%M:%S").strftime(common.DATE_FORMAT)

    def update_data(self, data):
        """Update internal data with the provided data.

        If internal data is empty, it sets the data; otherwise, it appends files
        and updates the end timestamp.

        Parameters
        ----------
        data : dict
            Data to update.

        """
        if self.is_empty():
            self.set_data(data)
        else:
            if data:
                [self._internal_data['files'].append(item) for item in data.get('files', [])]
                self._internal_data['end'] = utils.get_utc_strptime(data['end'], "%Y-%m-%d %H:%M:%S").strftime(common.DATE_FORMAT)

    def to_dict(self):
        """Return the internal data as a dictionary.

        Returns
        -------
        dict
            Internal data as a dictionary.

        """
        return self._internal_data
