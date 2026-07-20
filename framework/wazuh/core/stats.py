# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import contextlib
import json
from typing import Union

from wazuh.core import common, utils
from wazuh.core import wazuh_socket
from wazuh.core.exception import WazuhError, WazuhInternalError, WazuhException

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
    command = f"{str(agent_id).zfill(3)} {daemon} getstate"

    if next_page:
        command += " next"

    return command


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
