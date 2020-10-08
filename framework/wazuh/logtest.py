# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import WazuhError
from wazuh.core.logtest import send_logtest_msg
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=['logtest:run'], resources=['*:*:*'])
def run_logtest(token=None, event=None, log_format=None, location=None):
    """Get the logtest output after sending a JSON to its socket.

    Parameters
    ----------
    TODO

    Raises
    ------
    WazuhError(7000)
        If there are more kwargs than expected.

    Returns
    -------
    dict
        Logtest response after analyzing the event.
    """
    # Token could not be present
    if locals()['token'] is None:
        del locals()['token']

    response = send_logtest_msg(command='log_processing', params=locals())
    if response['error'] != 0:
        raise WazuhError(code=7000, extra_message=response.get('message', 'Could not parse error message'))

    return response


@expose_resources(actions=['logtest:end_session'], resources=['*:*:*'])
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

    response = send_logtest_msg(command='remove_session', params={'token': token})

    return response
