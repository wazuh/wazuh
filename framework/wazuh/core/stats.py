# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import contextlib
from typing import Union

from wazuh.core import common, utils
from wazuh.core import wazuh_socket
from wazuh.core.exception import WazuhInternalError

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
