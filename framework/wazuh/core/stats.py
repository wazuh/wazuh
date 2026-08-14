# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import contextlib

from wazuh.core import common, utils
from wazuh.core import wazuh_socket
from wazuh.core.exception import WazuhInternalError

def get_daemons_stats_socket(socket: str) -> dict:
    """Send message to Wazuh socket to get statistical information.

    Parameters
    ----------
    socket : str
        Full path of the socket to communicate with.

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
        command='getstats'
    )

    # Connect to socket
    try:
        s = wazuh_socket.WazuhSocketJSON(socket)
    except Exception:
        raise WazuhInternalError(1121, extra_message=socket)

    # Send message and receive socket response
    try:
        s.send(full_message)
        response = s.receive()
    finally:
        s.close()

    # Timestamps transformations
    with contextlib.suppress(KeyError):
        response['timestamp'] = utils.get_date_from_timestamp(response['timestamp'])
        response['uptime'] = utils.get_date_from_timestamp(response['uptime'])

    return response
