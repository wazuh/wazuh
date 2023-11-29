# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from datetime import datetime

import pytz

from wazuh.core.common import LOGTEST_SOCKET, DECIMALS_DATE_FORMAT, origin_module
from wazuh.core.wazuh_socket import WazuhSocketJSON, create_wazuh_socket_message
from wazuh.core.exception import WazuhError


def send_logtest_msg(command: str = None, parameters: dict = None) -> dict:
    """Connect and send a message to the logtest socket.

    Parameters
    ----------
    command: str
        Command to send to the logtest socket.
    parameters : dict
        Dict of parameters that will be sent to the logtest socket.

    Returns
    -------
    dict
        Response from the logtest socket.
    """
    full_message = create_wazuh_socket_message(origin={'name': 'Logtest', 'module': origin_module.get()},
                                               command=command,
                                               parameters=parameters)
    logtest_socket = WazuhSocketJSON(LOGTEST_SOCKET)
    logtest_socket.send(full_message)
    response = logtest_socket.receive(raw=True)
    logtest_socket.close()
    try:
        response['data']['output']['timestamp'] = datetime.strptime(
            response['data']['output']['timestamp'], "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(pytz.utc).strftime(
            DECIMALS_DATE_FORMAT)
    except KeyError:
        pass

    return response


def validate_dummy_logtest():
    """
    Validates a dummy log test by sending a log test message.

    Parameters
    ----------
    None

    Returns
    -------
    dict
        A dictionary containing the response from the log test.

    Raises
    ------
    WazuhError
        If an error occurs during the log test with error code 1113.
    """
    command = "log_processing"
    parameters = {"location": "dummy", "log_format": "syslog", "event": "Hello"}

    response = send_logtest_msg(command, parameters)
    if response.get('data', {}).get('codemsg', -1) == -1:
        raise WazuhError(1113)
