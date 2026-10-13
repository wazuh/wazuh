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


LOGTEST_ERROR_PREFIX = 'ERROR: '
# analysisd message IDs. In debug mode, analysisd prepends the source location to the message
LOGTEST_SESSION_ERROR_ID = '(7311)'
RULE_TREE_LIMIT_ERROR_ID = '(5108)'


def get_logtest_errors(messages: list) -> list:
    """Get the error messages of a logtest response, without the generic session error.

    Parameters
    ----------
    messages : list
        Messages of the logtest response, prefixed with their level.

    Returns
    -------
    list
        Error messages without their level prefix.
    """
    return [message[len(LOGTEST_ERROR_PREFIX):] for message in messages
            if message.startswith(LOGTEST_ERROR_PREFIX) and LOGTEST_SESSION_ERROR_ID not in message]


def validate_dummy_logtest() -> None:
    """Validates a dummy log test by sending a log test message.

    Raises
    ------
    WazuhError(1132)
        If the ruleset exceeds the rule tree node limit of analysisd.
    WazuhError(1113)
        If any other error occurs during the log test. The analysisd errors are added to the message.
    """
    command = "log_processing"
    parameters = {"location": "dummy", "log_format": "syslog", "event": "Hello"}

    response = send_logtest_msg(command, parameters)
    data = response.get('data', {})
    if data.get('codemsg', -1) == -1:
        errors = get_logtest_errors(data.get('messages', []))
        rule_tree_errors = [error for error in errors if RULE_TREE_LIMIT_ERROR_ID in error]
        if rule_tree_errors:
            raise WazuhError(1132, extra_message=' '.join(rule_tree_errors))
        raise WazuhError(1113, extra_message=' '.join(errors) or None)
