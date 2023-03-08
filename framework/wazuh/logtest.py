# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import WazuhError
from wazuh.core.logtest import send_logtest_msg
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=['logtest:run'], resources=['*:*:*'])
def run_logtest(token: str = None, event: str = None, log_format: str = None, location: str = None) -> dict:
    """Get the logtest output after sending a JSON to its socket.

    Parameters
    ----------
    token : str, optional
        Logtest session token. Default `None`
    event : str
        Log event.
    log_format : str
        Log format.
    location : str
        Log location.

    Raises
    ------
    WazuhError(7000)
        If there are more kwargs than expected.

    Returns
    -------
    dict
        Logtest response after analyzing the event.
    """
    local_vars = locals()
    # Token is not required
    if local_vars['token'] is None:
        del local_vars['token']

    response = send_logtest_msg(command='log_processing', parameters=local_vars)
    if response['error'] != 0:
        raise WazuhError(7000, extra_message=response.get('message', 'Could not parse error message'))

    return response


@expose_resources(actions=['logtest:run'], resources=['*:*:*'])
def end_logtest_session(token: str = None):
    """End the logtest session for the introduced token.

    Parameters
    ----------
    token : str
        Logtest session token.

    Returns
    -------
    dict
        Logtest response to the message.
    """
    if token is None:
        raise WazuhError(7001)

    response = send_logtest_msg(command='remove_session', parameters={'token': token})
    if response['error'] != 0:
        raise WazuhError(7000, extra_message=response.get('message', 'Could not parse error message'))

    return response
